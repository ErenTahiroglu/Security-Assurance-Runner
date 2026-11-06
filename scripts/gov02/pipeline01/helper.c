#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#define INERT_LIMIT 4096
static int prohibited_writes(void) {
  int fd=open("/input/report-template.json",O_WRONLY|O_NOFOLLOW);
  if(fd>=0){close(fd);return 1;}
  fd=open("/root-write-test",O_CREAT|O_WRONLY|O_EXCL,0600);
  if(fd>=0){close(fd);return 1;}
  return 0;
}
static int identity(void) {
  if(getuid()!=65532 || geteuid()!=65532)return 1;
  FILE *f=fopen("/proc/self/status","r");
  if(!f)return 1;
  char line[256];int cap=0,nnp=0;
  while(fgets(line,sizeof(line),f)) {
    if(strncmp(line,"CapEff:",7)==0 && strstr(line,"0000000000000000"))cap=1;
    if(strncmp(line,"NoNewPrivs:",11)==0 && strstr(line,"1"))nnp=1;
  }
  fclose(f);return cap && nnp ? 0 : 1;
}
static int copy_report(const char *mode) {
  int cfg=open("/config/approved.txt",O_RDONLY|O_NOFOLLOW);
  if(cfg<0)return 30;
  char c[64]={0};ssize_t cn=read(cfg,c,sizeof(c)-1);close(cfg);
  if(cn!=26 || strcmp(c,"SAR_INERT_PIPELINE_CONFIG\n")!=0)return 31;
  int input=open("/input/report-template.json",O_RDONLY|O_NOFOLLOW);
  if(input<0)return 32;
  char buf[INERT_LIMIT+1];ssize_t n=read(input,buf,sizeof(buf));close(input);
  if(n<=0||n>INERT_LIMIT)return 33;
  int fd=open("/output/report.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);
  if(fd<0)return 34;
  if(strcmp(mode,"partial")==0) {buf[0]='[';n=1;}
  if(strcmp(mode,"oversize")==0) {
    char block[4096];memset(block,'x',sizeof(block));
    for(int i=0;i<17;i++)if(write(fd,block,sizeof(block))!=(ssize_t)sizeof(block)){close(fd);return 35;}
  } else if(write(fd,buf,(size_t)n)!=n) {close(fd);return 36;}
  if(fsync(fd)!=0){close(fd);return 37;}
  if(close(fd)!=0)return 38;
  return 23; /* inert helper status only, never Gitleaks */
}
int main(int argc,char **argv) {
  if(argc!=2 || identity()!=0 || prohibited_writes()!=0)return 40;
  if(strcmp(argv[1],"sleep")==0){sleep(15);return 0;}
  if(strcmp(argv[1],"fail")==0)return 17;
  if(strcmp(argv[1],"copy")==0 || strcmp(argv[1],"partial")==0 || strcmp(argv[1],"oversize")==0)
     return copy_report(argv[1]);
  return 41;
}
