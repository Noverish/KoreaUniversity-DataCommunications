#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
 
#define BAUDRATE B38400
#define SERIALDEVICE "/dev/ttyS0"

#define PPPINITFCS16 0xffff /* Initial FCS value */   
#define PPPGOODFCS16 0xf0b8 /* Good final FCS value */   

#define TRUE 1
#define FALSE 0
#define GLOBAL_BUF_SIZE 65536

#define TIME_OUT_COUNTER_INIT 10  //상대방의 반응이 없이 몇 번 까지 conf_req를 보낼지
#define TIME_GAP_COUNTER 3 //매 req 사이사이가 몇 초인지

//LCP Option 타입
#define ASYNCMAP_TYPE 2
#define MAGIC_NUMBER_TYPE 5
#define ACCOMP_TYPE 8
#define PCOMP_TYPE 7

//IPCP Option 타입
#define IP_COMPRESS_TYPE 2
#define IP_ADDRESS_TYPE 3

//#define PPP_STATE_DEBUG
#define RCVD_BIT_DEBUG
#define SENT_BIT_DEBUG
//#define CRC_DEBUG
//#define PACKET_DEBUG

enum ppp_protocol {LCP = 0xC021, CCP = 0x80FD, IPCP = 0x8021};

enum lcp_code {
    CONF_REQ = 1, CONF_ACK = 2, CONF_NAK = 3, CONF_REJ = 4, 
    TERM_REQ = 5, TERM_ACK = 6, CODE_REJ = 7, PROTOCOL_REJ = 8,
    ECHO_REQ = 9, ECHO_REPLY = 10, DISCARD_REQ = 11};
char* code_to_string[] = {"","ConfReq","ConfAck","ConfNak","ConfRej","TermReq","TermAck",
                             "CodeRej","PtclRej","EchoReq","EchoRep","DscdReq"};

int layer_to_protocol[3] = {LCP, CCP, IPCP};
enum ppp_layer {layer_LCP, layer_CCP, layer_IPCP};
char *layer_to_string[] = {"layer_LCP", "layer_CCP", "layer_IPCP"};

enum ppp_event {   
    EVENT_UP, EVENT_DOWN, EVENT_OPEN, EVENT_CLOSE, EVENT_TO_PLUS, EVENT_TO_MINUS,   
    EVENT_RCR_PLUS, EVENT_RCR_MINUS, EVENT_RCA, EVENT_RCN, EVENT_RTR, EVENT_RTA,   
    EVENT_RUC, EVENT_RXJ_PLUS, EVENT_RXJ_MINUS, EVENT_RXR};   
char *event_to_string[] = {"UP", "DOWN", "OPEN", "CLOSE", "TO_PLUS", "TO_MINUS", 
                         "RCR_PLUS", "RCR_MINUS", "RCA", "RCN", "RTR", "RTA",
                         "RUC", "RXJ_PLUS", "RXJ_MINUS", "RXR"};
   
enum ppp_state {   
    state_Initial, state_Starting, state_Closed, state_Stopped, state_Closing, state_Stopping,   
    state_ReqSent, state_AckRcvd, state_AckSent, state_Opened, state_NoChange};   
char *state_to_string[] = {"Initial", "Starting", "Closed", "Stopped", "Closing", "Stopping", 
                         "ReqSent", "AckRcvd", "AckSent", "Opened", "NoChange"};
   
enum ppp_action {   
    none, irc, scr, tls, tlf, str, sta, sca, scn, scj,   
    tld, tlu, zrc, ser};
char *action_to_string[] = {"none", "irc", "scr", "tls", "tlf", "str", "sta", 
                         "sca", "scn", "scj", "tld", "tlu", "zrc", "ser"};   

//define structs=========================================================================
struct _Option {
    int type;
    int length;
    uint8_t *data;
    struct _Option* next;
};
typedef struct _Option* Option;

struct _Inside_Packet {
    int code;
    int id;
    int length;
    Option option;
};
typedef struct _Inside_Packet* Inside_Packet;

struct _PPP_Packet {
    int addr;
    int control;
    int protocol;
    Inside_Packet inside_packet;
    uint16_t crc;
};
typedef struct _PPP_Packet* PPP_Packet;

typedef struct _PPP_ACTION {
	int next_state;
	int action[3];
} PPP_ACTION;

//PPP State Machine table================================================================
PPP_ACTION ppp_dispatch[10][16] = {    //[state][event] => next_state, action   
	{ /* state_Initial */
		/* EVENT_UP */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Starting,{tls, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_NoChange,{none, none, none}},
	},
	{ /* state_Starting */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_ReqSent,{irc, scr, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Starting,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Initial,{tlf, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_NoChange,{none, none, none}},
	},
	{ /* state_Closed */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Initial,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_ReqSent,{irc, scr, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_Closed,{sta, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_Closed,{sta, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_Closed,{sta, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_Closed,{sta, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_Closed,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_Closed,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Closed,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_Closed,{none, none, none}},
	},
	{ /* state_Stopped */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Starting,{tls, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Stopped,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closed,{none, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_AckSent,{irc, scr, sca}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_ReqSent,{irc, scr, scn}},
		/* EVENT_RCA */(PPP_ACTION){state_Stopped,{sta, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_Stopped,{sta, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_Stopped,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_Stopped,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_Stopped,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_Stopped,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_Stopped,{none, none, none}},
	},
	{ /* state_Closing */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Initial,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_Closing,{str, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_Closed,{tlf, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_Closing,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_Closed,{tlf, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_Closing,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Closed,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_Closing,{none, none, none}},
	},
	{ /* state_Stopping */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Initial,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{none, none, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_Stopping,{str, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_Stopping,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_Stopping,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_Stopping,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_Stopping,{none, none, none}},
	},
	{ /* state_ReqSent */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Starting,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_ReqSent,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{irc, str, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_ReqSent,{scr, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_AckSent,{sca, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_ReqSent,{scn, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_AckRcvd,{irc, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_ReqSent,{irc, scr, none}},
		/* EVENT_RTR */(PPP_ACTION){state_ReqSent,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_ReqSent,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_ReqSent,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_ReqSent,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_ReqSent,{none, none, none}},
	},
	{ /* state_AckRcvd */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Starting,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_AckRcvd,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{irc, str, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_ReqSent,{scr, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_Opened,{sca, tlu, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_AckRcvd,{scn, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_ReqSent,{scr, none, none}},
		/* EVENT_RCN */(PPP_ACTION){state_ReqSent,{scr, none, none}},
		/* EVENT_RTR */(PPP_ACTION){state_ReqSent,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_ReqSent,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_AckRcvd,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_ReqSent,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_AckRcvd,{none, none, none}},
	},
	{ /* state_AckSent */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Starting,{none, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_AckSent,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{irc, str, none}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_AckSent,{scr, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_AckSent,{sca, none, none}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_ReqSent,{scn, none, none}},
		/* EVENT_RCA */(PPP_ACTION){state_Opened,{irc, tlu, none}},
		/* EVENT_RCN */(PPP_ACTION){state_AckSent,{irc, scr, none}},
		/* EVENT_RTR */(PPP_ACTION){state_ReqSent,{sta, none, none}},
		/* EVENT_RTA */(PPP_ACTION){state_AckSent,{none, none, none}},
		/* EVENT_RUC */(PPP_ACTION){state_AckSent,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_AckSent,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopped,{tlf, none, none}},
		/* EVENT_RXR */(PPP_ACTION){state_AckSent,{none, none, none}},
	},
	{ /* state_Opened */(PPP_ACTION)
		/* EVENT_UP */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_DOWN */(PPP_ACTION){state_Starting,{tld, none, none}},
		/* EVENT_OPEN */(PPP_ACTION){state_Opened,{none, none, none}},
		/* EVENT_CLOSE */(PPP_ACTION){state_Closing,{tld, irc, str}},
		/* EVENT_TO_PLUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_TO_MINUS */(PPP_ACTION){state_NoChange,{none, none, none}},
		/* EVENT_RCR_PLUS */(PPP_ACTION){state_AckSent,{tld, scr, sca}},
		/* EVENT_RCR_MINUS */(PPP_ACTION){state_ReqSent,{tld, scr, scn}},
		/* EVENT_RCA */(PPP_ACTION){state_ReqSent,{tld, scr, none}},
		/* EVENT_RCN */(PPP_ACTION){state_ReqSent,{tld, scr, none}},
		/* EVENT_RTR */(PPP_ACTION){state_Stopping,{tld, zrc, sta}},
		/* EVENT_RTA */(PPP_ACTION){state_ReqSent,{tld, scr, none}},
		/* EVENT_RUC */(PPP_ACTION){state_Opened,{scj, none, none}},
		/* EVENT_RXJ_PLUS */(PPP_ACTION){state_Opened,{none, none, none}},
		/* EVENT_RXJ_MINUS */(PPP_ACTION){state_Stopping,{tld, irc, str}},
		/* EVENT_RXR */(PPP_ACTION){state_Opened,{ser, none, none}},
	}
};

//variables==============================================================================
uint8_t buf[255];
uint8_t global_buf[GLOBAL_BUF_SIZE]; //End flag가 나올때 까지 쌓아두는 buf
int global_buf_len = 0;
int garbage_before_first_frame = TRUE; //맨 처음에 프로그램 실행되기 전에 버퍼에 있던 값을 무시 해주는 flag
int turn_on_record = FALSE; //이게 on이면 받은 octet을 global_buf에 넣어줌

int fd; //프레임을 보내고 받을 때 씀

int now_layer; //현재의 레이어가 LCP인지 IPCP인지
int now_state[3]; //현재 레이어의 state, 0은 LCP, 1은 CCP, 2는 IPCP

clock_t last_timer_millis; //가장 최근데 TO+ event가 발생한 milli second
clock_t last_echo_timer_millis;
int timer_on = FALSE;
int echo_timer_on = FALSE;
int counter; //몇 번 보냈는지 카운트

uint8_t magic_number[4] = {1,2,3,4};
uint8_t *your_ip; //상대방 아이피를 저장해 놓는 포인터
uint8_t my_ip[] = {0x0a, 0x01, 0x03, 0x0a};

int accomp_negotiate = TRUE; //LCP 협상 할 때 accomp를 켤 지 끌 지
int pcomp_negotiate = TRUE; //LCP 협상 할 때 pcomp를 켤 지 끌 지
int accomp_on = FALSE; //현재 accomp가 켜져있는지 꺼져 있는지
int pcomp_on = FALSE; //현재 pcomp가 켜져있는지 꺼져 있는지

//define functions=======================================================================
int remove_escape_bit(uint8_t *origin, int len);							//escape bit를 제거 하는 함수
PPP_Packet serial_to_packet(uint8_t *serial, int len);						//serial을 packet struct로 바꿔주는 함수
void packet_to_serial(PPP_Packet packet, uint8_t **serial_p, int *len_p);	//packet struct를 serial로 바꿔주는 함수
void print_packet(PPP_Packet packet);										//packet의 값을 octet단위로 구별해가며 출력
void print_packet_short(PPP_Packet packet);									//packet을 한 줄에 출력
Option get_option_by_type(PPP_Packet packet, int type);						//packet에서 type값으로 옵션을 추출

void process_packet(PPP_Packet received);									//받은 패킷을 처리
void process_event(PPP_Packet received, int event, int layer);				//패킷을 처리해서 생긴 이벤트를 처리
void do_action(PPP_Packet received, int action, int event, int state);		//이벤트를 처리해서 생긴 action을 처리
void timer(clock_t millis);	//while(1)에서 이 함수가 계속 호출 되는데 호출 될때의 millis를 계산해서 TO+, TO- 이벤트 생성
void echo_timer(clock_t millis);

void add_option_to_packet(PPP_Packet packet, int type, uint8_t *data, int data_len);	//패킷에 옵션 추가
PPP_Packet make_packet(uint16_t protocol, int code, int id);				//패킷을 생성
void add_crc(PPP_Packet packet);											//패킷에 crc 추가

void send_packet(PPP_Packet packet);										//패킷을 보냄

uint16_t make_crc(uint8_t* cp, int len);									//crc 생성
int check_crc(uint8_t* cp, int len);										//crc 체크

uint32_t serial_to_number(uint8_t *serial, int len);	//단순히 debug할 때 필요한 serial을 number로 바꾸는 함수

//=======================================================================================
int main(int argc, char **argv) {
    int res, k;
    struct termios oldtio, newtio;

    bzero(&buf, sizeof(buf));    
    fd = open(SERIALDEVICE, O_RDWR | O_NOCTTY, O_NONBLOCK);
    if(fd<0) {
        perror(SERIALDEVICE);
        exit(-1);
    }    
    tcgetattr(fd, &oldtio); 

    bzero(&newtio, sizeof(newtio));
    newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;
    newtio.c_iflag = IGNPAR | ICRNL;
 
    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &newtio);
    fflush(stdin);
    fflush(stdout);
    
    for(k=0; k<255; k++) {
        buf[k] = 0x00;
    }
    tcflush(fd, TCIFLUSH);
    tcflush(fd, TCIFLUSH);
    tcflush(fd, TCIFLUSH);

    now_layer = layer_LCP; //현재 layer를 LCP로 설정
    now_state[0] = now_state[1] = now_state[2] = state_Initial; //모든 layer의 state를 Initial로 설정

	//프로그램 옵션 값을 보고 accomp와 pcomp를 켤지 끌지 결정
	int i;
	for(i = 1; i < argc; i++) {
		if(strcmp(argv[i], "noaccomp"))
			accomp_negotiate = FALSE;
		if(strcmp(argv[i], "nopcomp"))
			pcomp_negotiate = FALSE;
	}

    process_event(NULL, EVENT_UP, layer_LCP); //처음 up 이벤트 발생시켜서 처리
	process_event(NULL, EVENT_OPEN, layer_LCP); //처음 up 이벤트 발생시켜서 처리

    while(1) {
        fflush(stdin);
        fflush(stdout);

		//timer가 켜져있으면 timer함수 호출
        if(timer_on) {
            timer(clock());
        }

		if(echo_timer_on) {
			echo_timer(clock());
		}

        res = read(fd, buf, 255);
        if(res) {
#ifdef RCVD_BIT_DEBUG
			printf("rcvd : ");
#endif // RCVD_BIT_DEBUG
            for (k=0 ; k<res;k++) {
                int bit = buf[k];
#ifdef RCVD_BIT_DEBUG
                printf("%02X ",bit);
#endif // RCVD_BIT_DEBUG
                if(garbage_before_first_frame) { //첫 프레임이 오기 전에 있는 쓰레기 값들을 무시
                    if(bit == 0x7E) { //start flag가 오면 global buf에 쓰기 시작
                        turn_on_record = TRUE;
                        garbage_before_first_frame = FALSE;
                    }
                } else {
                    if(turn_on_record) {
                        if(bit == 0x7E) { //end flag가 오면
                            turn_on_record = FALSE; 
							//일단 다음 start flag가 오기 전까지 기록하지 않습니다.
#ifdef RCVD_BIT_DEBUG
							printf("\n");
#endif // RCVD_BIT_DEBUG
							global_buf_len = remove_escape_bit(global_buf, global_buf_len); 
							//global_buf에 있는 escape bit를 제거하고

							if(check_crc(global_buf, global_buf_len - 2)) { //crc를 체크합니다.
								PPP_Packet received = serial_to_packet(global_buf, global_buf_len); 
								//crc가 옳으면 이 serial을 packet struct로 바꿔줍니다.
								printf("  rcvd ");
								print_packet_short(received); //패킷 정보를 한줄로 출력하고
#ifdef PACKET_DEBUG
								print_packet(received);
#endif // PACKET_DEBUG
								process_packet(received); //이 패킷을 처리합니다.
							}
							else { //crc 오류면 이 프레임을 무시하고 다음 프레임을 받습니다.
								printf("<<<<Invalid CRC>>>>\n");
							}
							global_buf_len = 0;
#ifdef RCVD_BIT_DEBUG
							if(k != res - 1)
								printf("rcvd : ");
#endif // RCVD_BIT_DEBUG
                        }
                        else
                            global_buf[global_buf_len++] = bit; 
						//end flag가 오기 전까지 global buf에 기록
                    } else {
						turn_on_record = TRUE;
                        if(bit != 0x7E) {
                            global_buf[global_buf_len++] = bit;
                        }
                    }
                }
            }
#ifdef RCVD_BIT_DEBUG
			printf("\n");
#endif // RCVD_BIT_DEBUG
        }
    } //while end
    tcsetattr(fd,TCSANOW, &oldtio);    
    return 0;
}


//packet_functions=======================================================================
int remove_escape_bit(uint8_t *origin, int len) {

    uint8_t *serial = (uint8_t*) calloc(len, sizeof(uint8_t));
    int origin_i, new_i, i;

    for(origin_i = 0, new_i = 0; origin_i < len; origin_i++, new_i++) {
        if(origin[origin_i] == 0x7D) {
            origin_i++;
            serial[new_i] = origin[origin_i] ^ 0x20;
        } else {
            serial[new_i] = origin[origin_i];
        }
    }

	for(i = 0; i < new_i; i++) {
		origin[i] = serial[i];
	}

	return new_i;
}

PPP_Packet serial_to_packet(uint8_t *serial, int len) {
    len = remove_escape_bit(serial, len);

    PPP_Packet packet = (PPP_Packet) malloc(sizeof(struct _PPP_Packet));
    Inside_Packet inside = (Inside_Packet) malloc(sizeof(struct _Inside_Packet));
    int now_len = 4, cnt = 0;

    if(serial[0] != 0xFF) {
        packet->addr = 0xFF;
        packet->control = 0x03;
    } else {
        packet->addr = serial[cnt++];
        packet->control = serial[cnt++];
    }
    packet->protocol += serial[cnt++] * 256;
    packet->protocol += serial[cnt++];

    packet->inside_packet = inside;
    inside->code = serial[cnt++];
    inside->id = serial[cnt++];
    inside->length += serial[cnt++] * 256;
    inside->length += serial[cnt++];

    if(packet->inside_packet->code == ECHO_REQ || packet->inside_packet->code == ECHO_REPLY) {
        Option new_option = (Option) malloc(sizeof(struct _Option));
        if(new_option == NULL) {
            printf("serial_to_packet - new_option is null\n");
            assert(0);
        }

        uint8_t *data = (uint8_t*) calloc(2, sizeof(uint8_t));
        if(data == NULL) {
            printf("serial_to_packet - data is null\n");
            assert(0);
        }

        new_option->type = serial[cnt++];
        new_option->length = serial[cnt++];

        data[0] = serial[cnt++];
        data[1] = serial[cnt++];

        new_option->data = data;
        packet->inside_packet->option = new_option;
    } else {
        Option last_option = NULL;
        while(now_len < inside->length) {
            Option new_option = (Option) malloc(sizeof(struct _Option));
            if(new_option == NULL) {
                printf("serial_to_packet - new_option is null\n");
                assert(0);
            }
            int i;

            new_option->type = serial[cnt++];
            new_option->length = serial[cnt++];
            new_option->data = (uint8_t*) calloc(new_option->length - 2, sizeof(uint8_t));

            if(new_option->data == NULL) {
                printf("serial_to_packet - new_option->data is null\n");
                printf("serial_to_packet - packet->ppp_protocol is %02X\n",packet->protocol);
                printf("serial_to_packet - inside->lcp_code is %02X\n",inside->code);
                printf("serial_to_packet - inside->id is %02X\n",inside->id);
                printf("serial_to_packet - inside->length is %02X\n",inside->length);
                printf("serial_to_packet - new_option->type is %02X\n",new_option->type);
                printf("serial_to_packet - new_option->length is %02X\n",new_option->length);
                assert(0);
            }

            for(i = 0; i < new_option->length - 2; i++) {
                (new_option->data)[i] = serial[cnt++];
            }

            now_len += new_option->length;

            if(last_option == NULL) {
                inside->option = new_option;
                last_option = new_option;
            } else {
                last_option->next = new_option;
                last_option = new_option;
            }
        }
    }

    packet->crc += serial[cnt++] * 256;
    packet->crc += serial[cnt++];

    return packet;
}

void packet_to_serial(PPP_Packet packet, uint8_t **serial_p, int *len_p) {
    uint8_t *serial = (uint8_t*) calloc(packet->inside_packet->length + 6, sizeof(uint8_t));
    int cnt = 0;

	//printf("accomp_on : %s\n", (accomp_on) ? "TRUE" : "FALSE");
	if(!accomp_on) {
		serial[cnt++] = packet->addr;
		serial[cnt++] = packet->control;
	}
    serial[cnt++] = packet->protocol / 256;
    serial[cnt++] = packet->protocol % 256;
    serial[cnt++] = packet->inside_packet->code;
    serial[cnt++] = packet->inside_packet->id;
    serial[cnt++] = packet->inside_packet->length / 256;
    serial[cnt++] = packet->inside_packet->length % 256;

    if(packet->inside_packet->code == ECHO_REQ || packet->inside_packet->code == ECHO_REPLY) {
        serial[cnt++] = packet->inside_packet->option->type;
        serial[cnt++] = packet->inside_packet->option->length;
        serial[cnt++] = packet->inside_packet->option->data[0];
        serial[cnt++] = packet->inside_packet->option->data[1];
    } else {
        Option option = packet->inside_packet->option;
        for(;option != NULL;option = option->next) {
            serial[cnt++] = option->type;
            serial[cnt++] = option->length;

            int i = 0;
            for(;i < option->length - 2; i++) {
                serial[cnt++] = (option->data)[i];
            }
        }
    }
    serial[cnt++] = packet->crc / 256;
    serial[cnt++] = packet->crc % 256;

    *serial_p = serial;
    *len_p = cnt;
}

void print_packet(PPP_Packet packet) {
    int i;

    printf("\n");
    printf("ppp_addr      : %02X\n", packet->addr);
    printf("ppp_control   : %02X\n", packet->control);
    printf("ppp_protocol  : %02X\n", packet->protocol);
    printf("  inside_code   : %02X\n", packet->inside_packet->code);
    printf("  inside_id     : %02X\n", packet->inside_packet->id);
    printf("  inside_length : %02X\n", packet->inside_packet->length);

	if(packet->inside_packet->code == ECHO_REPLY || packet->inside_packet->code == ECHO_REQ) {
		uint8_t type = packet->inside_packet->option->type;
		uint8_t length = packet->inside_packet->option->length;
		uint8_t data0 = packet->inside_packet->option->data[0];
		uint8_t data1 = packet->inside_packet->option->data[1];
		printf("  magic number : %02X%02X%02X%02X\n", type, length, data0, data1);
	} else {
		Option option = packet->inside_packet->option;
		for(; option != NULL; option = option->next) {
			printf("    option_type   : %02X\n", option->type);
			printf("    option_length : %02X\n", option->length);
			printf("    option_data   : ");

			for(i = 0; i<option->length - 2; i++) {
				printf("%02X ", (option->data)[i]);
			}
			printf("\n");
		}
	}

    printf("ppp_crc       : %X\n", packet->crc);
}

void print_packet_short(PPP_Packet packet) {
    printf("[");

    if(packet->protocol == LCP)
        printf("LCP ");
    else if(packet->protocol == CCP)
        printf("CCP ");
    else if(packet->protocol == IPCP)
        printf("IPCP ");

    printf("%s ",code_to_string[packet->inside_packet->code]);

	printf("id=0x%X ", packet->inside_packet->id);

	if(packet->protocol == LCP) {
		if(packet->inside_packet->code == ECHO_REQ || packet->inside_packet->code == ECHO_REPLY) {
			uint8_t type = packet->inside_packet->option->type;
			uint8_t length = packet->inside_packet->option->length;
			uint8_t *data = packet->inside_packet->option->data;
			printf("magic=0x%02X%02X%02X%02X ", type, length, data[0], data[1]);
		} else {
			Option option = get_option_by_type(packet, ASYNCMAP_TYPE);
			if(option != NULL) {
				printf("<asyncmap 0x%X> ",serial_to_number(option->data, option->length - 2));
			}

			option = get_option_by_type(packet, MAGIC_NUMBER_TYPE);
			if(option != NULL) {
				printf("<magic 0x");
				int i;
				for(i = 0; i < option->length - 2; i++)
					printf("%02X", (option->data)[i]);
				printf("> ");
			}

			option = get_option_by_type(packet, PCOMP_TYPE);
			if(option != NULL) {
				printf("<pcomp> ");
			}

			option = get_option_by_type(packet, ACCOMP_TYPE);
			if(option != NULL) {
				printf("<accomp> ");
			}
		}
	} else if(packet->protocol == IPCP) {
		Option option = get_option_by_type(packet, IP_COMPRESS_TYPE);
		if(option != NULL) {
			printf("<compress 0x");
			int i;
			for(i = 0; i < option->length - 2; i++)
				printf("%02X", (option->data)[i]);
			printf("> ");
		}

		option = get_option_by_type(packet, IP_ADDRESS_TYPE);
		if(option != NULL) {
			printf("<addr ");
			int i;
			for(i = 0; i < option->length - 2; i++)
				printf("%d.", (option->data)[i]);
			printf("> ");
		}
	}

    printf("]\n");
}

Option get_option_by_type(PPP_Packet packet, int type) {
    Option option = packet->inside_packet->option;
    for(;option != NULL; option = option->next) {
        if(option->type == type) {
            return option;
        }
    }
    return NULL;
}

//packet_process_functions===============================================================
void process_packet(PPP_Packet received) {
    int event = -1;
    switch(received->inside_packet->code) { //받은 packet으로 이벤트를 생성
        case CONF_REQ : {//LCP 협상때 서로의 옵션이 다르면 RCR-, 같으면 RCR+
			if(received->protocol == LCP) { 
				if(accomp_negotiate == FALSE && get_option_by_type(received, ACCOMP_TYPE) != NULL) {
					event = EVENT_RCR_MINUS;
					break;
				}
				if(pcomp_negotiate == FALSE && get_option_by_type(received, PCOMP_TYPE) != NULL) {
					event = EVENT_RCR_MINUS;
					break;
				}
			}
            event = EVENT_RCR_PLUS;
            break;
        }
        case CONF_ACK : { //conf_ack이 오면 accomp와 pcomp를 켜거나 끈다.
            event = EVENT_RCA;
			if(accomp_negotiate) accomp_on = TRUE;
			if(pcomp_negotiate) pcomp_on = TRUE;
            break;
        }
        case CONF_NAK :
        case CONF_REJ : {
            event = EVENT_RCN;
            break;
        }
        case TERM_REQ : {
            event = EVENT_RTR;
            break;
        }
        case TERM_ACK : {
            event = EVENT_RTA;
            break;
        }
        case CODE_REJ :
        case PROTOCOL_REJ : {
            event = EVENT_RXJ_PLUS;
            break;
        }
        case ECHO_REQ :
        case ECHO_REPLY :
        case DISCARD_REQ : {
            event = EVENT_RXR;
            break;
        }             
    }

    int layer; //받은 패킷의 프로토콜에 따라 이 이벤트를 처리할 layer를 구별
    if(received->protocol == LCP) layer = layer_LCP;
    else if(received->protocol == CCP) layer = layer_CCP;
    else if(received->protocol == IPCP) layer = layer_IPCP;
    else assert(FALSE); //모르는 프토로콜이면 프로그램 정지

    if(received->inside_packet->code == CONF_REQ) //conf_req가 오면 관련 레이어를 open함
        process_event(received, EVENT_OPEN, layer);

    process_event(received, event, layer); //찾아낸 이벤트 처리
}

void process_event(PPP_Packet received, int event, int layer) {

#ifdef PPP_STATE_DEBUG
	printf("    FROM : event - %s, layer - %s, state - %s %s %s\n",
		   event_to_string[event],
		   layer_to_string[layer],
		   state_to_string[now_state[0]],
		   state_to_string[now_state[1]],
		   state_to_string[now_state[2]]);
#endif // PPP_STATE_DEBUG

	if(event == EVENT_RCN) { //상대방과 LCP 옵션 타협할 때 rej을 받으면 옵션 정보를 수정
		Option option = received->inside_packet->option;
		for(; option != NULL; option = option->next) {
			int nak_option_type = option->type;

			if(nak_option_type == ACCOMP_TYPE)
				accomp_negotiate = !accomp_negotiate;
			if(nak_option_type == PCOMP_TYPE)
				pcomp_negotiate = !pcomp_negotiate;
		}
	}

	//이벤트와 state를 가지고 action을 찾아서 action실행
    int i;
    for(i = 0; i < 3; i++) {
        if(ppp_dispatch[now_state[layer]][event].action[i] != none) {
            do_action(received, ppp_dispatch[now_state[layer]][event].action[i], event, now_state[layer]);
        }
    }

	//이벤트와 state를 가지고 다음 state 설정
    int next_state = ppp_dispatch[now_state[layer]][event].next_state;
    if(next_state != state_NoChange)
        now_state[layer] = next_state;

#ifdef PPP_STATE_DEBUG
    printf("    TO   : event - %s, layer - %s, state - %s %s %s\n",
        event_to_string[event],
        layer_to_string[layer],
        state_to_string[now_state[0]], 
        state_to_string[now_state[1]], 
        state_to_string[now_state[2]]);
#endif // PPP_STATE_DEBUG
}

void do_action(PPP_Packet received, int action, int event, int state) {
#ifdef PPP_STATE_DEBUG
    printf("        do_action - %s\n",action_to_string[action]);
#endif // PPP_STATE_DEBUG

    switch(action) {
        case tlu :{ 
            //this ppp_layer up
            if(now_layer == layer_LCP) { //현재 레이어가 LCP이면
                now_layer = layer_IPCP;	//현재는 layer를 LCP와 IPCP밖에 안쓰니까 LCP에서 up하면 바로 IPCP로 넘어감
                process_event(received, EVENT_UP, now_layer);
				process_event(NULL, EVENT_OPEN, now_layer);
			} else if(now_layer == layer_IPCP) { 
				//IPCP에서 tlu action이 발생하면
				//LCP와 IPCP의 모든 옵션 협상이 끝났다는 의미이므로
				//echo를 10초에 한 번씩 보내는 timer를 킨다.
				echo_timer_on = TRUE;
				last_echo_timer_millis = clock();

				//tlu action이 발생한지 10초후에 echo를 보내는 것이 아니라
				//tlu action이 발생한 즉시 echo를 보내고 이후 10초마다
				//echo를 보낸다
				received->protocol = LCP;
				received->inside_packet->code = ECHO_REQ;
				received->inside_packet->option->type = magic_number[0];
				received->inside_packet->option->length = magic_number[1];
				received->inside_packet->option->data[0] = magic_number[2];
				received->inside_packet->option->data[1] = magic_number[3];
				add_crc(received);
				send_packet(received);
			}
            break;
        }
        case tld :{
            //this ppp_layer down
            if(now_layer == layer_IPCP) { //현재 레이어가 IPCP이면
                now_layer = layer_LCP;  //현재는 layer를 LCP와 IPCP밖에 안쓰니까 LCP에서 down하면 바로 IPCP로 넘어감
                process_event(received, EVENT_DOWN, now_layer);
            }
            break;
        }
        case tls :{
            break;
        }
        case tlf :{
            break;
        }
        case irc :{
            //initialize restart count

            if(event == EVENT_RCA) { //ACK이 오면 더이상 REQ를 보낼 필요가 없으니까 timer를 끔
                timer_on = FALSE;
                counter = TIME_OUT_COUNTER_INIT;
            } else { //아니면 타이머를 켬
                timer_on = TRUE;
                last_timer_millis = clock();
                counter = TIME_OUT_COUNTER_INIT;
            }
            break;
        }
        case zrc :{
            //zero restart count
            break;
        }
        case scr :{//현재 레이어에 따라 관련 REQ를 보냄
            if(now_layer == layer_LCP) {
                PPP_Packet send = make_packet(LCP, CONF_REQ, 1);
                add_option_to_packet(send, ASYNCMAP_TYPE, (uint8_t[]){0, 0, 0, 0}, 4);
                add_option_to_packet(send, MAGIC_NUMBER_TYPE, magic_number, 4);
				if(pcomp_negotiate)
					add_option_to_packet(send, PCOMP_TYPE, NULL, 0);
				if(accomp_negotiate)
					add_option_to_packet(send, ACCOMP_TYPE, NULL, 0);
                add_crc(send);

                send_packet(send);
            } else if(now_layer == layer_CCP) {
                
            } else if(now_layer == layer_IPCP) {
                PPP_Packet send = make_packet(IPCP, CONF_REQ, 1);
                add_option_to_packet(send, IP_COMPRESS_TYPE, (uint8_t[]){0x00, 0x2D, 0x0F, 0x01}, 4);
                add_option_to_packet(send, IP_ADDRESS_TYPE, my_ip, 4);
                add_crc(send);

                send_packet(send);
            }
            break;
        }
        case sca :{
            //send configure ack
            received->inside_packet->code = CONF_ACK;

            add_crc(received);
            send_packet(received);
            break;
        }
        case scn :{
            //send-configure-nak/rej
            PPP_Packet send = make_packet(layer_to_protocol[now_layer], CONF_REJ, 1);
			if(pcomp_negotiate == FALSE)
				add_option_to_packet(send, PCOMP_TYPE, NULL, 0);
			if(accomp_negotiate == FALSE)
				add_option_to_packet(send, ACCOMP_TYPE, NULL, 0);
            add_crc(send);

            send_packet(send);

            break;
        }
        case str :{
            //send terminate request
            PPP_Packet send = make_packet(layer_to_protocol[now_layer], TERM_REQ, 1);
            add_crc(send);

            send_packet(send);

            break;
        }
        case sta :{
            //send terminate ack
            PPP_Packet send = make_packet(layer_to_protocol[now_layer], TERM_ACK, 1);
            add_crc(send);

            send_packet(send);

            break;
        }
        case scj :{
            //send lcp_code reject
            PPP_Packet send = make_packet(layer_to_protocol[now_layer], CODE_REJ, 1);
            add_crc(send);

            send_packet(send);

            break;
        }
        case ser :{
            //send echo reply
			if(received->inside_packet->code == ECHO_REQ) {
				received->inside_packet->code = ECHO_REPLY;
				received->inside_packet->option->type = magic_number[0];
				received->inside_packet->option->length = magic_number[1];
				received->inside_packet->option->data[0] = magic_number[2];
				received->inside_packet->option->data[1] = magic_number[3];
				add_crc(received);
				send_packet(received);
			}
            break;
        }
    }
}

void timer(clock_t millis) {
    if(millis - last_timer_millis > CLOCKS_PER_SEC * TIME_GAP_COUNTER) {
        if(counter > 0) {
            process_event(NULL, EVENT_TO_PLUS, now_layer);
        }
        else {
            process_event(NULL, EVENT_TO_MINUS, now_layer);
            timer_on = FALSE;
        }

        last_timer_millis = millis;
        counter--;
    }
}

void echo_timer(clock_t millis) {
	if(millis - last_echo_timer_millis > CLOCKS_PER_SEC * 10) {
		uint8_t tmp[2] = {-1, -1};

		PPP_Packet send = make_packet(LCP, ECHO_REQ, 1);
		add_option_to_packet(send, -1, tmp, 2);
		send->inside_packet->option->type = magic_number[0];
		send->inside_packet->option->length = magic_number[1];
		send->inside_packet->option->data[0] = magic_number[2];
		send->inside_packet->option->data[1] = magic_number[3];
		add_crc(send);
		send_packet(send);

		last_echo_timer_millis = millis;
	}
}

//packet_generate_functions==============================================================
void add_option_to_packet(PPP_Packet packet, int type, uint8_t *data, int data_len) {
    Inside_Packet inside_packet = packet->inside_packet;
    Option new_option = (Option) malloc(sizeof(struct _Inside_Packet));

    new_option->type = type;
    new_option->length = data_len + 2;
    new_option->data = data;

    inside_packet->length += data_len + 2;

    if(inside_packet->option == NULL)
        inside_packet->option = new_option;
    else {
        Option option = inside_packet->option;
        for(;option->next != NULL;option = option->next);
        option->next = new_option;
    }
}

PPP_Packet make_packet(uint16_t protocol, int code, int id) {
    PPP_Packet new_packet = (PPP_Packet) malloc(sizeof(struct _PPP_Packet));
    Inside_Packet new_inside = (Inside_Packet) malloc(sizeof(struct _Inside_Packet));

    new_packet->addr = 0xFF;
    new_packet->control = 0x03;
    new_packet->protocol = protocol;
    new_packet->inside_packet = new_inside;
    new_inside->code = code;
    new_inside->id = id;
    new_inside->length = 4;

    return new_packet;
}

void add_crc(PPP_Packet packet) {
    uint8_t *serial;
    int len = 0;

    packet_to_serial(packet, &serial, &len);

    uint16_t crc = make_crc(serial, len - 2);

    packet->crc = (crc % 256) << 8;
    packet->crc += (crc / 256);
}

//send===================================================================================
void send_octet(uint8_t octet) {
    uint8_t send_buf[2];

    if(octet < 0x20 || octet == 0x7D || octet == 0x7E) {
        send_buf[0] = 0x7D;
        send_buf[1] = octet ^ 0x20;
        write(fd,send_buf,2);
#ifdef SENT_BIT_DEBUG
		printf("%02X %02X ", send_buf[0], send_buf[1]);
#endif // SENT_BIT_DEBUG
    } else {
        send_buf[0] = octet;
        write(fd,send_buf,1);
#ifdef SENT_BIT_DEBUG
		printf("%02X ", send_buf[0]);
#endif // SENT_BIT_DEBUG
    }
}

void send_packet(PPP_Packet packet) {
    uint8_t flag = 0x7E;
    uint8_t *serial;
    int len, i;

    packet_to_serial(packet, &serial, &len);

#ifdef SENT_BIT_DEBUG
	printf("sent : 7E ");
#endif // SENT_BIT_DEBUG
    write(fd,&flag,1);
    for(i = 0; i < len; i++) {
        send_octet(serial[i]);
    }
    write(fd,&flag,1);
#ifdef SENT_BIT_DEBUG
	printf("7E\n");
#endif // SENT_BIT_DEBUG

    printf("  sent ");
    print_packet_short(packet);
}

//crc_check==============================================================================
static uint16_t crc_table[256] = {   
0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,   
0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,   
0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,   
0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,   
0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,   
0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,   
0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,   
0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,   
0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,   
0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,   
0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,   
0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,   
0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,   
0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,   
0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,   
0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,   
0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,   
0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,   
0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,   
0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,   
0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,   
0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,   
0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,   
0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,   
0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,   
0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,   
0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,   
0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,   
0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,   
0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,   
0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,   
0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78   
};   
uint16_t crc(uint16_t fcs, char* cp, int len) {   
    while (len--)   
    fcs = (fcs >> 8) ^ crc_table[(fcs ^ *cp++) & 0xff];   
    return (fcs);   
}
uint16_t make_crc(uint8_t* cp, int len) {   
    uint16_t trialfcs;   
    /* add on output */   
    trialfcs = crc( PPPINITFCS16, cp, len );   
    trialfcs ^= 0xffff; /* complement */   
    //cp[len] = (trialfcs & 0x00ff); /* least significant byte first */   
    //cp[len+1] = ((trialfcs >> 8) & 0x00ff);
    return trialfcs;
}
int check_crc(uint8_t* cp, int len) {
#ifdef CRC_DEBUG
	int i;
	printf("crc check : ");
	for(i = 0; i < len + 2; i++) {
		printf("%02X ", cp[i]);
	}
	printf("\n");
#endif // CRC_DEBUG

    uint16_t trialfcs;   
    /* check on input */   
    trialfcs = crc( PPPINITFCS16, cp, len + 2 );   
    if ( trialfcs == PPPGOODFCS16 )   
        return 1;
    else 
        return 0;
}

//essential
uint32_t serial_to_number(uint8_t *serial, int len) {
	uint32_t ans = 0;
	int i;
	for(i = 0; i < len; i++) {
		ans *= 256;
		ans += serial[i];
	}

	return ans;
}
