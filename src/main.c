
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>

#define THREAD_COUNT_DEFAULT 2000 /*默认使用的线程数量*/
#define PORT_NUMBER_MAX 65535   /*最大端口数*/

void mulite_thread_run(const char *dest_ip,int from_port,int end_port,int thread_count);
int asyn_conn(char *ip,int port);
void scan_port(char *ip,int from_port,int end_port,int *result);
void do_operate_task(void *arg);

int **p_thread_from;

struct thread_operation
{
  char *ip;/*目标IP*/
  int thread_idx;/*线程索引*/
  int from;/*开始端口*/
  int to;/*结束端口*/
};

int main(int argc, const char * argv[])
{
  if (argc < 2) {
    printf("./scanner <目标IP地址>\n");
    return 0;
  }

  printf("扫描开始...\n");

  const char *dest_ip = argv[1];  /*目标IP地址*/
  int from_port = 0;//atoi(argv[2]);/*开始端口*/
  int end_port = PORT_NUMBER_MAX;//atoi(argv[3]);/*结束端口*/
  int thread_count = THREAD_COUNT_DEFAULT;
  int open[PORT_NUMBER_MAX];
  if(argc == 5){/*设置线程数*/
      thread_count = atoi(argv[4]);
  }
  p_thread_from = (int **)malloc(sizeof(int*)*thread_count);
  mulite_thread_run(dest_ip, from_port, end_port,thread_count);

  return 0;
}

/**
 * 使用多线程进行扫描
 * @param dest_ip 目标IP地址
 * @param from_port 开始端口
 * @param end_port 结束端口
 * @param thread_count 使用的线程数
 */
void mulite_thread_run(const char *dest_ip,int from_port,int end_port,int thread_count)
{
    pthread_t *p_thread = (pthread_t*)malloc(sizeof(pthread_t)*thread_count);

    int port_count = end_port - from_port + 1;
  	for (int i = 0; i < thread_count;i++){
        int offset = (port_count / thread_count)*i;
        int count = (port_count - offset) < (port_count/thread_count)  ? (port_count - offset) : port_count/thread_count;

        struct thread_operation *op;
  		  op = (struct thread_operation*)malloc(sizeof(struct thread_operation));
  		  op->ip = dest_ip;
  		  op->from = from_port + offset;
  		  op->to = op->from + count - 1;
  		  op->thread_idx = i;
  		  pthread_create(&p_thread[i], NULL, do_operate_task,(void *)op);
  	}

    for (int j = 0; j < thread_count; j++) {
        void *thread_return;
        int ret = pthread_join(p_thread[j],&thread_return);/*等待第一个线程退出，并接收它的返回值*/
        if(ret != 0){
            printf("调用pthread_join获取线程1返回值出现错误!\n");
		    }
        else {
            //printf("pthread_join调用成功!线程1退出后带回的值是%d\n",(int)thread_return);
        }
    }

    printf("\n------------------\n开放端口:\n");
    for (int k = 0 ; k < thread_count; k++) {
        int count = p_thread_from[k][0];
        for(int i = 1 ; i <= count;i++)
        {
            printf("%d 开放\n",p_thread_from[k][i]);
        }
    }

    printf("扫描结束\n------------------\n");
}

void do_operate_task(void *arg)
{
    struct thread_operation *op;
    op = (struct thread_operation *)arg;
    int count = op->to - op->from + 2;
    int *result = (int *)malloc(sizeof(int)*count);
    scan_port(op->ip, op->from, op->to, result);
    p_thread_from[op->thread_idx] = result;
    pthread_exit(NULL);
}

/*扫描端口*/
void scan_port(char *ip,int from_port,int end_port,int *result)
{
  int count = 0;
  for (int i = from_port; i <= end_port; i++) {
    printf("开始扫描 %d号 端口\n",i);
    int r = -1;
    if ((r=asyn_conn(ip, i)) == 0) {
        count++;
        result[count]= i;
    }
  }
  result[0] = count;
}

/**
 * 测试指定端口是否可用
 * @param ip 目标ip地址
 * @param port 端口
*/
int asyn_conn(char *ip,int port)
{
  int flags, n, error;
  fd_set rset,wset;
  struct timeval tval;

  FD_ZERO(&wset);
  FD_ZERO(&rset);
  tval.tv_sec = 1;
  tval.tv_usec = 0;

   /*建立TCP套接字,并将sockfb设置为非阻塞模式*/
  int sockfd = socket(PF_INET, SOCK_STREAM,0);
  flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in address;
  bzero(&address, sizeof(address));
  address.sin_family = AF_INET;
  inet_pton(AF_INET, ip, &address.sin_addr);
  address.sin_port = htons(port);

  error = 0;
  if((n = connect(sockfd,(struct sockaddr *)&address,sizeof(address)))<0){
	/*
	 * 非阻塞模式下,connect返回为-1,错误码为EINPROGRESS,
	 * 通过是否可写入数据可以判定socket是否连接
	 * 通过select和poll模型可以判断是否可写
	*/
      if(errno != EINPROGRESS)
      {
          printf("Connecting 1 error!\n");
          return -1;
      }
      else if(n==0){
		       //This case may be happen on localhost
           printf("Connecting 1 success! \n");
          return 0;
      }
  }
  FD_SET(sockfd,&rset);
  wset=rset;
  //usleep(10);

  /* Do whatever we want while the connect is taking place */

  int rst = select(sockfd+1, &rset,&wset,NULL,&tval);

  switch (rst) {
      case -1:
          perror("Select error");
		exit(-1);
      case 0:
          close(sockfd);
          printf("Timed Out!\n");
          break;
      default:
          if (FD_ISSET(sockfd,&rset)||FD_ISSET(sockfd,&wset)) {
              int error;
              socklen_t len = sizeof (error);
              if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR,&error,&len) < 0){
                  printf ("getsockopt fail,connected fail\n");
                  return -1;
              }

              if(error == 0){
                  printf ("--->端口 %d 开放!\n",port);
                  return 0;
              }
          }
          close(sockfd);
  }
  return -1;
}
