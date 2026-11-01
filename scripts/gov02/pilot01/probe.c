/* GOV-02 PILOT-01 original inert containment probe: NOT a scanner. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int fail(const char *s){fprintf(stderr,"PREFLIGHT_ERROR:%s\n",s);return 1;}
static int status_ok(void){
 FILE*f=fopen("/proc/self/status","r");if(!f)return fail("PROC_UNREADABLE");
 char line[256];int cap=0,nnp=0;
 while(fgets(line,sizeof line,f)){
  if(!strncmp(line,"CapEff:",7)&&strstr(line,"0000000000000000"))cap=1;
  if(!strncmp(line,"NoNewPrivs:",11)&&strstr(line,"1"))nnp=1;
 }
 fclose(f);return cap&&nnp?0:fail("PRIVILEGE_FLAGS_MISSING");
}
static int fs(void){
 if(getuid()!=65532||geteuid()!=65532)return fail("WRONG_UID");
 if(status_ok())return 1;
 if(access("/var/run/docker.sock",F_OK)==0||access("/checkout/.git/config",F_OK)==0||
    access("/home/runner/.config",F_OK)==0)return fail("HOST_PATH_EXPOSED");
 char buf[64]={0};int fd=open("/input/marker.txt",O_RDONLY);
 if(fd<0)return fail("INPUT_MISSING");
 ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);
 if(n<=0||strcmp(buf,"SAR_INERT_DEMO_ABCD1234\n"))return fail("INPUT_CHANGED");
 fd=open("/input/marker.txt",O_WRONLY|O_APPEND);
 if(fd>=0){close(fd);return fail("INPUT_WRITABLE");}
 fd=open("/rootfs_write_test",O_WRONLY|O_CREAT|O_EXCL,0600);
 if(fd>=0){close(fd);return fail("ROOTFS_WRITABLE");}
 fd=open("/output/receipt.txt",O_WRONLY|O_CREAT|O_EXCL,0600);
 if(fd<0)return fail("OUTPUT_UNWRITABLE");
 const char msg[]="PREFLIGHT_FS_OK\n";
 ssize_t written=write(fd,msg,sizeof(msg)-1);close(fd);
 if(written!=(ssize_t)(sizeof(msg)-1))return fail("OUTPUT_WRITE_FAILED");
 puts("PREFLIGHT_FS_OK");return 0;
}
static int net(const char *ip,const char*port){
 char*end=NULL;long p=strtol(port,&end,10);
 if(!end||*end||p<1||p>65535)return fail("INVALID_PORT");
 struct sockaddr_in dst={0};dst.sin_family=AF_INET;dst.sin_port=htons((unsigned short)p);
 if(inet_pton(AF_INET,ip,&dst.sin_addr)!=1)return fail("INVALID_IP");
 int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return 42;
 int result=connect(fd,(struct sockaddr*)&dst,sizeof dst);close(fd);
 if(!result){puts("PREFLIGHT_LOCAL_ENDPOINT_REACHABLE");return 0;}return 42;
}
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"fs"))return fs();
 if(argc==4&&!strcmp(argv[1],"net"))return net(argv[2],argv[3]);
 if(argc==2&&!strcmp(argv[1],"sleep")){sleep(45);return 0;}
 return fail("UNSUPPORTED_MODE");
}
