#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>


typedef struct buffer
{
    char *file_buf;
    unsigned int length;
    char file_str[0x50];
}Fbuf;



int namespacedProcessPid;
char *namespaceMountBaseDir;
char name[0x10];
Fbuf file[3] = {0};
int choicer = 0;

void read_n(char *s,unsigned int length)
{
    for(int i = 0;i<length;i++)
    {
        if(read(0,&s[i],1) < 0)
            exit(-1);
        if(s[i] == '\n'){
            s[i] = 0;
            return;
        }
    }
}

int read_int()
{
    char s[100] = {0};
    read_n(s,100);
    return atoi(s);
}

int usernsChildFunction() {
    while(geteuid()!=0) {
        sched_yield();
  }
    int result=mount("tmpfs", "/tmp", "tmpfs", MS_MGC_VAL, NULL);
    if(result)
        exit(-1);
  if(chdir("/tmp"))
    exit(-1);
    sleep(1000000);
}

void init()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
    char *stackData=(char*)malloc(1<<20);
    namespacedProcessPid=clone(usernsChildFunction, stackData+(1<<20),
        CLONE_NEWUSER|CLONE_NEWNS|SIGCHLD, NULL);
    if(namespacedProcessPid==-1) {
        puts("error!");  
        exit(-1);
    }
    char idMapFileName[128];
    char idMapData[128];
	char pathBuffer[PATH_MAX];
	int result=snprintf(pathBuffer, sizeof(pathBuffer), "/proc/%d/cwd",
	namespacedProcessPid);
	namespaceMountBaseDir=strdup(pathBuffer);
    sprintf(idMapFileName, "/proc/%d/setgroups", namespacedProcessPid);
    int setGroupsFd=open(idMapFileName, O_WRONLY);
    result=write(setGroupsFd, "deny", 4);
    close(setGroupsFd);
    
    sprintf(idMapFileName, "/proc/%d/uid_map", namespacedProcessPid);
    int uidMapFd=open(idMapFileName, O_WRONLY);
    sprintf(idMapData, "0 %d 1\n", getuid());
    result=write(uidMapFd, idMapData, strlen(idMapData));
    close(uidMapFd);

    sprintf(idMapFileName, "/proc/%d/gid_map", namespacedProcessPid);
    int gidMapFd=open(idMapFileName, O_WRONLY);
    sprintf(idMapData, "0 %d 1\n", getgid());
    result=write(gidMapFd, idMapData, strlen(idMapData));
    close(gidMapFd);
    sleep(1);
    printf("tmpfs ready!\n");
	result=chdir(namespaceMountBaseDir);
	if(result)
		exit(-1);
    printf("input your home's name: ");
    read_n(name,0x10);
    char home[0x14];
    if(strchr(name,'/') || strchr(name,'.'))
    {
        puts("you can't use that name,use default name [home]");
        strcpy(name,"home");
        mkdir("home", 0755);
    }else{
        if(mkdir(name, 0755))
            mkdir("home", 0755);
    }
    strcpy(home,name);
    home[strlen(home)] = '/';
    strcat(home,"flag");
    int handle=open(home, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY, 0644);
    write(handle,"flag{This_is_Fake}",19);
    close(handle);
}

void print_menu()
{
    puts("\
   000  000   000000000000000000000000 000000    00000    0000     000000\n\
  000  000 00000000000000000000000000 0000000  0000000  00000    0000000 \n\
 000   000 0000  00   000    000      00  000 0000 000  00000    000 000 \n\
 000  000 0000        000    000         0000 000  000    000    0000000 \n\
 00000000 000         000    000         000  000  000    000    000000  \n\
 00000000 000        000    00000000    0000 000   000    000    00000   \n\
 000000000000        000    0000000    0000  000   000   000    0000000  \n\
 00   0000000        000    000       0000   000  0000   000    000 000  \n\
000  000 0000        000    000      000     000  000    000   000  000  \n\
000  000  00000000   000    000     0000000  00000000 00000000 00000000  \n\
000  000  0000000   000    000      0000000   000000  00000000  000000   \n\
000  000   000000   000     00      0000000    000    00000000   0000    \n");
}


void createDirectoryRecursive(char *pathName) {
  char pathBuffer[PATH_MAX];
  int pathNameLength=0;
  while(1) {
    char *nextPathSep=strchr(pathName+pathNameLength, '/');
    if(nextPathSep) {
      pathNameLength=nextPathSep-pathName;
    } else {
      pathNameLength=strlen(pathName);
    }
    snprintf(pathBuffer, sizeof(pathBuffer), "%s/%.*s",
        namespaceMountBaseDir, pathNameLength, pathName);
    mkdir(pathBuffer, 0755);
    if(!pathName[pathNameLength])
      break;
    pathNameLength++;
  }
    char *check = canonicalize_file_name(pathName);
    if(check != NULL)
    {
        free(check);
    }else{
    	puts("mkdir:create failed.");
        exit(-1);
    }
}

void ls(char *path)
{
	if(path == NULL)
    {
    	char s[2] = ".";
    	path = s;
    }
    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir(path)) == NULL)
        exit(2);
    while((dirp = readdir(dp)) != NULL)
        printf("%s  ",dirp->d_name);
    closedir(dp);
    putchar('\n');
}

void cat(char *path)
{
    if(path == NULL)
    {
        puts("Usage:cat [path]");
        return;
    }
    if(strstr(path,"..") || path[0] == '/')
    {
        puts("you can't go out of tmpfs");
           return;
    }
    for(int i = 0;i<3;i++){
        if(!strcmp(path,file[i].file_str))
        {
            puts(file[i].file_buf);
            choicer = (i + 1) % 3;
            return;
        }
    }
    char p[0x100] = {0};
    FILE *fp = fopen(path,"r");
    if(fp > 0)
    {
        fread(p,0x100,1,fp);
        puts(p);
        fclose(fp);
    }
    else
    {
        puts("No such file!");
    }
}

void do_mkdir(char *path)
{
    if(path == NULL)
    {
        puts("Usage:mkdir [path]");
        return;
    }
    createDirectoryRecursive(path);
}


void do_mkfile(char *path)
{
    if(path == NULL)
    {
        puts("Usage:mkfile [path]");
        return;
    }
    if(strstr(path,"..") || path[0] == '/')
    {
        puts("you can't go out of tmpfs");
           return;
    }
    for(int i = 0;i<3;i++){
        if(!strcmp(path,file[i].file_str))
        {
            printf("write something:");
            read_n(file[i].file_buf,file[i].length);
            choicer = (i + 1) % 3;
            return;
        }
    }
    if(file[choicer].file_buf){
    	FILE *fp=fopen(file[choicer].file_str, "w");
    	fwrite(file[choicer].file_buf,1,file[choicer].length,fp);
    	fclose(fp);
        free(file[choicer].file_buf);
    }
    strcpy(file[choicer].file_str,path);
    int fd=open(path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY, 0644);
    if(fd<0)
    {
        puts("mkfile:create failed.");
        exit(-1);
    }
    printf("write something:");
    char contect[0x1000];
    read_n(contect,0x1000);
    write(fd,contect,0x1000);
    file[choicer].file_buf = strdup(contect);
    file[choicer].length = strlen(contect);
    close(fd);
    choicer = (choicer+1) % 3;
}

int cmd_choicer(char *cmd)
{
	if(!strcmp(cmd,"ls"))
		return 1;
	if(!strcmp(cmd,"mkdir"))
		return 2;
    if(!strcmp(cmd,"mkfile"))
        return 3;
    if(!strcmp(cmd,"cat"))
        return 4;
	if(!strcmp(cmd,"exit"))
		return 5;
	return -1;
}

void run()
{
	char cmd[0x50];
	char *arg;
	while(1){
		printf("\033[1;32m%s@ubuntu\033[37m:\033[34m%s\033[37m$ ",name,"/tmp");
		read_n(cmd,0x50);
		if((arg = strchr(cmd,' ')) != 0){
			arg[0] = 0;
			arg++;
			if(*arg == 0)
				arg = NULL;
		}
		switch(cmd_choicer(cmd))
		{
			case 1:
				ls(arg);
				break;
			case 2:
				do_mkdir(arg);
				break;
			case 3:
                do_mkfile(arg);
                break;
            case 4:
                cat(arg);
                break;
			case 5:
				exit(0);
				break;
			default:
				puts("invalid command!");
		}
	}
}

int main()
{
	init();
    print_menu();
    puts("Welcome to use my tmpfs,you can use these commands:");
    puts("[ls] [mkdir] [mkfile] [cat] [exit]");
	run();
}