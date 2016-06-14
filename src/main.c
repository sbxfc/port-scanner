
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

int conn_nonb(char *ip,int port,int nsec);
void scan_r(char *ip,int port_from,int port_to,int *result);
void thread_run(void *arg);
void mulite_thread_run(char *ip,int port_from,int port_to,int thread_count);

int **res;

struct argument
{
    char *ip;
    int port_from;
    int port_to;
    int i;
};

int main(int argc, const char * argv[])
{
    if (argc < 4) {
        printf("port_scan {要扫描的IP} {开始端口} {结束端口} {线程数}\n");
        return 0;
    }
	
    printf("-->开始扫描\n");
	sleep(1);
    
    char *ip = argv[1];
    int port_from = atoi(argv[2]);
    int port_to = atoi(argv[3]);
    int open[65535];
    int count = 0;
    
    if(argc == 5)
    {
		//使用多线程
        int ts = atoi(argv[4]);
        res = (int **)malloc(sizeof(int*)*ts);
        mulite_thread_run(ip, port_from, port_to,ts);
    }
	else{
		
        for (int i = port_from; i <= port_to; i++)
		{
            printf("开始扫描 %d号 端口\n",i);
            int r = -1;
            if ((r = conn_nonb(ip, i, 100)) == 0) {
                open[count] = i;
                count++;
            }
        }

		printf("\n扫描结果:\n------------------\n");
		for(int i = 0 ; i <= count;i++)
		{
			printf("端口 %d 开放\n",open[i]);
		}
    
		printf("扫描结束\n------------------\n");
    }
    
    return 0;
}

/**
 * @param thread_count 线程数量
 */
void mulite_thread_run(char *ip,int port_from,int port_to,int thread_count)
{

    pthread_t *thread;
    thread = (pthread_t*)malloc(sizeof(pthread_t)*thread_count);
	
	int port_count = port_to - port_from + 1;
	for (int i = 0; i < thread_count;i++){
		int offset = (port_count / thread_count)*i;
		struct argument *arg;
		arg = (struct argument*)malloc(sizeof(struct argument));
		arg->ip = ip;
		arg->port_from = port_from + offset;
		int count = (port_count - offset) < (port_count/thread_count)  ? (port_count - offset) : port_count/thread_count;
		arg->port_to = arg->port_from + count - 1;
		arg->i=i;
		pthread_create(&thread[i], NULL, thread_run,(void *)arg);
	}

    
    for (int j = 0; j < thread_count; j++) {
        void *thread_return;
        int ret=pthread_join(thread[j],&thread_return);/*等待第一个线程退出，并接收它的返回值*/
        if(ret!=0){
            printf("调用pthread_join获取线程1返回值出现错误!\n");
		}
        else {
            //printf("pthread_join调用成功!线程1退出后带回的值是%d\n",(int)thread_return);
		}
    }
    
    printf("\n扫描结果:\n------------------\n");
    for (int k = 0 ; k < thread_count; k++) {
        int count = res[k][0];
        for(int i = 1 ; i <= count;i++)
        {
            printf("%d 开放\n",res[k][i]);
        }
    }
    
    printf("扫描结束\n------------------\n");
}

void thread_run(void *arg)
{
    struct argument *arg_thread1;/*这里定义了一个指向argument类型结构体的指针arg_thread1，用它来接收传过来的参数的地址*/
    
    arg_thread1=(struct argument *)arg;
    int size = arg_thread1 -> port_to - arg_thread1->port_from + 2;
    int *result = (int *)malloc(sizeof(int)*size);
    scan_r(arg_thread1->ip, arg_thread1->port_from, arg_thread1->port_to, result);
    res[arg_thread1->i] = result;
    pthread_exit(NULL);
}

void scan_r(char *ip,int port_from,int port_to,int *result)
{
    int count = 0;
    for (int i = port_from; i <= port_to; i++) {
        printf("开始扫描 %d号 端口\n",i);
        
        int r = -1;
        if ((r=conn_nonb(ip, i, 100)) == 0) {
            count++;
            result[count]= i;
        }
        
    }
    result[0] = count;
   
}

/**
 * 测试指定端口是否可用
 * @param ip ip地址
 * @param port 端口
 * @param nsec 没用到
*/
int conn_nonb(char *ip,int port,int nsec)
{
    int flags, n, error;
    //socklen_t len;
    fd_set rset,wset;
    struct timeval tval;
    
    FD_ZERO(&wset);
    FD_ZERO(&rset);
    tval.tv_sec = 1;
    tval.tv_usec = 0;
    //struct servent *sent;
    
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
                if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR,&error,&len) < 0)
                {
                    printf ("getsockopt fail,connected fail\n");
                    return -1;
                }
                if(error==0)
                {
                    printf (">>端口 %d 开放!\n",port);
                    return 0;
                }


            }
            close(sockfd);
    }
    return -1;
}


