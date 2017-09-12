
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
#include <arpa/inet.h>

#define NUMBER_OF_THREADS_USED 200
#define SYSTEM_PORT_MAX 65535

void mulite_thread_run(const char *dest_address,int start_port,int end_port,int thread_count);
int asyn_con(char *ip,int port);
void scan_port(char *ip,int start_port,int end_port,int *result);
void scan_by_thread(void *arg);

int **p_thread;

struct thread_task
{
  char *ip;     /*目标IP*/
  int thread_idx;/*线程索引*/
  int from;/*开始端口*/
  int to;/*结束端口*/
};

int main(int argc, const char * argv[]){

  if (argc < 2) {
    printf("Please use:\n./scan <dest_addressess>\n");
    return 0;
  }

  printf("Start scanning after a second!\n");
  sleep(1);

  //Destination adress.
  const char *dest_address = argv[1];

  int start_port = 0;             //atoi(argv[2]);
  int end_port = SYSTEM_PORT_MAX; //atoi(argv[3]);
  int thread_count = NUMBER_OF_THREADS_USED;
  int port_open[SYSTEM_PORT_MAX];

  p_thread = (int **)malloc(sizeof(int*)*thread_count);
  mulite_thread_run(dest_address, start_port, end_port,thread_count);

  return 0;
}

/**
 * scan by multi-thread
 * @param dest_address Destination adress.
 * @param start_port
 * @param end_port
 * @param thread_count
 */
void mulite_thread_run(const char *dest_address,int start_port,int end_port,int thread_count)
{
    pthread_t *p = (pthread_t*)malloc(sizeof(pthread_t)*thread_count);

    int port_count = end_port - start_port + 1;
    if(port_count > 0){

      //每个线程使用扫描端口数
      int ports_per_thread = port_count / thread_count;
    	for (int i = 0; i < thread_count;i++){
          int offset = ports_per_thread*i;
          int count = (port_count - offset) < ports_per_thread  ? (port_count - offset) : ports_per_thread;

          struct thread_task *task;
    		  task = (struct thread_task*)malloc(sizeof(struct thread_task));
    		  task->ip = (char *)dest_address;
    		  task->from = start_port + offset;
    		  task->to = task->from + count - 1;
    		  task->thread_idx = i;
    		  pthread_create(&p[i], NULL, (void  *)scan_by_thread,(void *)task);
    	}

      for (int j = 0; j < thread_count; j++) {
          void *thread_return;
          int rst = pthread_join(p[j],&thread_return);/*等待第一个线程退出，并接收它的返回值*/
          if(rst != 0){
              //printf("调用pthread_join获取线程1返回值出现错误!\n");
              printf("pthread_join error!\n");
  		    }
          else {
              //printf("pthread_join调用成功!线程1退出后带回的值是%d\n",(int)thread_return);
          }
      }

      printf("------------Open ports-------------\n");
      for (int k = 0 ; k < thread_count; k++) {
          int count = p_thread[k][0];
          for(int i = 1 ; i <= count;i++){
              printf("[%d OPEN]\n",p_thread[k][i]);
          }
      }
    }

    printf("------------End-------------\n");
}

void scan_by_thread(void *arg)
{
    struct thread_task *task = (struct thread_task *)arg;
    int count = task->to - task->from + 2;
    int *result = (int *)malloc(sizeof(int)*count);
    scan_port(task->ip, task->from, task->to, result);
    p_thread[task->thread_idx] = result;
    pthread_exit(NULL);
}

/*扫描端口*/
void scan_port(char *ip,int start_port,int end_port,int *result)
{
  int count = 0;
  for (int i = start_port; i <= end_port; i++) {
    printf("Scaning port %d.\n",i);
    int r = -1;
    if ((r=asyn_con(ip, i)) == 0) {
        count++;
        result[count]= i;
    }
  }
  result[0] = count;
}

/**
 * @param ip Destination address
 * @param port
*/
int asyn_con(char *ip,int port)
{
  int flags, n, error;
  fd_set rset,wset;
  struct timeval timeout;//timeout setting.

  FD_ZERO(&wset);
  FD_ZERO(&rset);
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

   /*Create a socket connect and set it as asynchronous*/
  int sockfd = socket(AF_INET/*IPv4*/, SOCK_STREAM,0);
  flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in address;
  bzero(&address, sizeof(address));
  address.sin_family = AF_INET;
  inet_pton(AF_INET, ip, &address.sin_addr);
  address.sin_port = htons(port);

  /*
   * 非阻塞模式下,connect返回-1,错误码为EINPROGRESS,
   * 通过是否可写入数据可以判定socket是否连接
   * 通过select和poll模型可以判断是否可写
  */
  error = 0;
  if((n = connect(sockfd,(struct sockaddr *)&address,sizeof(address))) < 0){

      if(errno != EINPROGRESS)
      {
          printf("Connecting 1 error!\n");
          return -1;
      }
      else if(n == 0){
		      //This case may be happen on localhost
          printf("Connecting 1 success! \n");
          return 0;
      }
  }
  FD_SET(sockfd,&rset);
  wset=rset;
  //usleep(10);

  /* Do whatever we want while the connect is taking place */

  int rst = select(sockfd+1, &rset,&wset,NULL,&timeout);

  switch (rst) {
      case -1:
          perror("select()");
		      return -1;
          //exit(-1);
      case 0:
          close(sockfd);
          printf("No data within 1 seconds.\n");
          break;
      default:
          //printf("Data is available now.\n");
          if (FD_ISSET(sockfd,&rset)||FD_ISSET(sockfd,&wset)) {
              int error;
              socklen_t len = sizeof (error);
              if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR,&error,&len) < 0){
                  printf ("getsockopt fail,connected fail\n");
                  close(sockfd);
                  return -1;
              }

              if(error == 0){
                  printf ("--->Port %d open!\n",port);
                  close(sockfd);
                  return 0;
              }
          }
          close(sockfd);
  }
  close(sockfd);
  return -1;
}
