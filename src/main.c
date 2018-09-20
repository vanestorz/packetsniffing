#include <gtk/gtk.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

void ProcessPacket(unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void PrintData(unsigned char*, int);
int sniff();
int readlog();

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,others=0,total=0,i,j;

GtkWidget *g_lbl_tcp;
GtkWidget *g_lbl_udp;
GtkWidget *g_lbl_others;
GtkWidget *entry_total;
GtkWidget *logview;
GtkWidget *scrolled_window;
GtkTextBuffer *buffertext;
GtkTextIter iter;

int main(int argc, char *argv[])
{
  GtkBuilder *builder;
  GtkWidget *window;


  gtk_init(&argc, &argv);

  builder = gtk_builder_new();
  gtk_builder_add_from_file (builder, "glade/packet_sniffing.glade",NULL);

  window = GTK_WIDGET(gtk_builder_get_object(builder, "packet_sniffing"));
  gtk_builder_connect_signals(builder, NULL);

  // UI pointers
  g_lbl_tcp = GTK_WIDGET(gtk_builder_get_object(builder,"lbl_tcp"));
  g_lbl_udp = GTK_WIDGET(gtk_builder_get_object(builder,"lbl_udp"));
  g_lbl_others = GTK_WIDGET(gtk_builder_get_object(builder,"lbl_others"));
  entry_total = GTK_WIDGET(gtk_builder_get_object(builder,"tb_entry"));
  scrolled_window = GTK_WIDGET(gtk_builder_get_object(builder,"scrolled_window"));
  logview = GTK_WIDGET(gtk_builder_get_object(builder,"logview"));

  //textview Buffer
  buffertext = gtk_text_view_get_buffer(GTK_TEXT_VIEW(logview));

  g_object_unref(builder);

  gtk_widget_show(window);
  gtk_widget_show(scrolled_window);
  gtk_main();

  return 0;
}


void on_btn_start_clicked()
{
  sniff();
}

int sniff(){
  int count=0;
  char str_tcp[30] = {0};
  char str_udp[30] = {0};
  char str_others[30] = {0};
  const gchar *var_total;
  int saddr_size , data_size, total_packets;
  struct sockaddr saddr;

  var_total = gtk_entry_get_text(GTK_ENTRY(entry_total));
  total_packets = atoi(var_total);

  unsigned char *buffer = (unsigned char *) malloc(65536); //Alokasi memori
  printf("\n%d\n",total_packets);

  logfile=fopen("log.txt","w");
  if(logfile==NULL)
  {
      printf("Tidak bisa memuat file log.txt");
  }
  printf("Mulai...\n");

  int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

  if(sock_raw < 0)
  {
      //Print error
      perror("Socket Error");
      return 1;
  }
  while(count<total_packets)
  {
      saddr_size = sizeof saddr;
      //Terima Paket
      data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
      if(data_size <0 )
      {
          printf("Recvfrom error , gagal mendapatkan packets\n");
          return 1;
      }
      //Memproses Paket
      ProcessPacket(buffer , data_size);
      count++;
  }
  close(sock_raw);

  gtk_text_buffer_set_text(buffertext, "Sniffing berhasil dilakukan\n\nSilahkan klik tombol Load Log File untuk memuat data log . . .", -1);

  sprintf(str_tcp,"%d",tcp);
  sprintf(str_udp,"%d",udp);
  sprintf(str_others,"%d",others);
  gtk_label_set_text(GTK_LABEL(g_lbl_tcp), str_tcp);
  gtk_label_set_text(GTK_LABEL(g_lbl_udp), str_udp);
  gtk_label_set_text(GTK_LABEL(g_lbl_others), str_others);

  return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol)
    {
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;

        default:
            ++others;
            break;
    }
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile , "Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");


    PrintData(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]);

                else fprintf(logfile , ".");
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);

        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile , "   ");
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}

void on_btn_log_clicked()
{
  readlog();
}

int readlog(){
  FILE *logfile;
  gchar *logstring = malloc(1024);

  logfile = fopen("log.txt", "r");
  if (logfile == NULL) {
    perror ("Gagal membuka file log. . .");
    return 1;
  }
  gtk_text_buffer_set_text(buffertext, " ", -1);
  while(fgets (logstring, 1024,  logfile) != NULL){
      gtk_text_buffer_get_end_iter(buffertext, &iter);
      gtk_text_buffer_insert(buffertext,&iter, logstring, -1);
      }
      fclose(logfile);

      return 0;
}

void on_window_main_destroy()
{
  gtk_main_quit();
}
