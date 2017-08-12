//
//  smbHeader.cpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#include "smbHeader.hpp"
#include<sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* SMB request state */
enum smb_req_state {
    SMB_REQUESTING,
    SMB_TREE_CONNECT,
    SMB_OPEN,
    SMB_DOWNLOAD,
    SMB_UPLOAD,
    SMB_CLOSE,
    SMB_TREE_DISCONNECT,
    SMB_DONE
};

/* SMB request data */
struct smb_request {
    enum smb_req_state state;
    char *share;
    char *path;
    unsigned short tid; /* Even if we connect to the same tree as another */
    unsigned short fid; /* request, the tid will be different */
//    CURLcode result;
};


/* SMB is mostly little endian */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
defined(__OS400__)
static unsigned short smb_swap16(unsigned short x)
{
    return (unsigned short) ((x << 8) | ((x >> 8) & 0xff));
}

static unsigned int smb_swap32(unsigned int x)
{
    return (x << 24) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) |
    ((x >> 24) & 0xff);
}

#ifdef HAVE_LONGLONG
static unsigned long long smb_swap64(unsigned long long x)
{
    return ((unsigned long long) smb_swap32((unsigned int) x) << 32) |
    smb_swap32((unsigned int) (x >> 32));
}
#else
static unsigned __int64 smb_swap64(unsigned __int64 x)
{
    return ((unsigned __int64) smb_swap32((unsigned int) x) << 32) |
    smb_swap32((unsigned int) (x >> 32));
}
#endif
#else
#  define smb_swap16(x) (x)
#  define smb_swap32(x) (x)
#  define smb_swap64(x) (x)
#endif


void SMB::smb_format_message( struct smb_header *h,
                               unsigned char cmd, size_t len)
{
    struct smb_conn *smbc ;//= &conn->proto.smbc;
    struct smb_request *req ;//= conn->data->req.protop;
    unsigned int pid;
    memset(h, 0, sizeof(*h));
    h->nbt_length = htons((unsigned short) (sizeof(*h) - sizeof(unsigned int) +
                                            len));
    memcpy((char *)h->magic, "\xffSMB", 4);
    h->command = cmd;
    h->flags = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
    h->flags2 = smb_swap16(SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAME);
    h->uid = smb_swap16(2);
    h->tid = smb_swap16(3);
    pid = getpid();
    h->pid_high = smb_swap16((unsigned short)(pid >> 16));
    h->pid = smb_swap16((unsigned short) pid);
}


#define CLIENTNAME "zorik"
#define OS "Windows"

bool SMB::smb_format_setup(struct smb_setup *setup)
{
    
    memset(setup, 0 , sizeof(struct smb_setup));
    char *p = setup->bytes;
    unsigned char lm_hash[21];
    unsigned char lm[24];
    unsigned char nt_hash[21];
    unsigned char nt[24];
    size_t byte_count = sizeof(lm) + sizeof(nt);
    byte_count += strlen(this->m_connection.user) + strlen(this->m_connection.domain);
    byte_count += strlen(OS) + strlen(CLIENTNAME) + 4; /* 4 null chars */
    if(byte_count > sizeof(setup->bytes))
        return false;
//    Curl_ntlm_core_mk_lm_hash(conn->data, conn->passwd, lm_hash);
//    Curl_ntlm_core_lm_resp(lm_hash, smbc->challenge, lm);

    memset(nt, 0, sizeof(nt));
    setup->word_count = SMB_WC_SETUP_ANDX;
    setup->andx.command = SMB_COM_NO_ANDX_COMMAND;
    setup->max_buffer_size = smb_swap16(MAX_MESSAGE_SIZE);
    setup->max_mpx_count = smb_swap16(1);
    setup->vc_number = smb_swap16(1);
    setup->session_key = smb_swap32(this->m_connection.session_key);
    setup->capabilities = smb_swap32(SMB_CAP_LARGE_FILES);
    setup->lengths[0] = smb_swap16(sizeof(lm));
    setup->lengths[1] = smb_swap16(sizeof(nt));
    memcpy(p, lm, sizeof(lm));
    p += sizeof(lm);
    memcpy(p, nt, sizeof(nt));
    p += sizeof(nt);

    byte_count = p - setup->bytes;
    setup->byte_count = smb_swap16((unsigned short)byte_count);
//    return smb_send_message(conn, SMB_COM_SETUP_ANDX, &msg,
//                            sizeof(msg) - sizeof(msg.bytes) + byte_count);
    
    
    return true;
}


 int SMB::smb_send(size_t len,
                    size_t upload_size)
{
    ssize_t bytes_written;
    bytes_written = send(m_socket , m_uploadbuffer,
                        len, 0);
    
    if(bytes_written)
    {
        this->m_connection.send_size = len;
        this->m_connection.sent = bytes_written;
        this->m_connection.upload_size = upload_size;

        return bytes_written;
    }
  
    return false;
}

int SMB::smb_send_message(unsigned char cmd,
                                 const void *msg, size_t msg_len)
{
    
//    smb_format_message((struct smb_header *)m_uploadbuffer,
//                       cmd, msg_len);
//    memcpy(m_uploadbuffer + sizeof(struct smb_header),
//           msg, msg_len);
//    
//
//    return smb_send(sizeof(struct smb_header) + msg_len, 0);
    return 1;
}


int SMB:: smb_recv_message(void **msg)
{
    struct smb_conn *smbc = &this->m_connection;// &conn->proto.smbc;
    char *buf = smbc->recv_buf;
    ssize_t bytes_read;
    size_t nbt_size;
    size_t msg_size;
    size_t len = MAX_MESSAGE_SIZE - smbc->got;
    char buffer[2000];
    int result;
//    bytes_read = recv(m_socket, buf + smbc->got, len, 0);
        bytes_read = recv(m_socket, buffer, 2000, 0);
    *msg = buffer;

    if(bytes_read)
        return bytes_read;
    if(!bytes_read)
        return result;
    smbc->got += bytes_read;
    /* Check for a 32-bit nbt header */
    if(smbc->got < sizeof(unsigned int))
        return result;
//    nbt_size = Curl_read16_be((unsigned char *)(buf + sizeof(unsigned short))) +
    sizeof(unsigned int);
    if(smbc->got < nbt_size)
        return result;
    msg_size = sizeof(struct smb_header);
    if(nbt_size >= msg_size + 1) {
        /* Add the word count */
        msg_size += 1 + ((unsigned char) buf[msg_size]) * sizeof(unsigned short);
        if(nbt_size >= msg_size + sizeof(unsigned short)) {
            /* Add the byte count */
//            msg_size += sizeof(unsigned short) +
//            Curl_read16_le((unsigned char *)&buf[msg_size]);
//            if(nbt_size < msg_size)
//                return result;
        }
    }
    *msg = buf;
    return bytes_read;
}

// PUBLIC
 int SMB::smb_send_negotiate()
{
    const char *msg = "\x00\x0c\x00\x02NT LM 0.12";
//    return smb_send_message(SMB_COM_NEGOTIATE, msg, 15);
    
    struct smb_header h;
    smb_format_message(&h,
                       SMB_COM_NEGOTIATE, 15);
    
    memcpy(m_uploadbuffer,&h, sizeof(smb_header));
    memcpy(m_uploadbuffer + sizeof(struct smb_header),
           msg, 15);
    
    return smb_send(sizeof(struct smb_header) + 15, 0);


}

int SMB:: smb_send_setup(){
    
//    const char *msg = "\x00\x0c\x00\x02NT LM 0.12";
    //    return smb_send_message(SMB_COM_NEGOTIATE, msg, 15);
    
    struct smb_header h;
    struct smb_setup setup;
    
    smb_format_message(&h,
                       SMB_COM_SETUP_ANDX, sizeof( smb_header)+ sizeof( smb_setup));
    printf("size of smb_header: %d\n", sizeof(smb_header));
    printf("size of smb_setup: %d\n", sizeof(smb_setup));

    smb_format_setup(&setup);
    
    memcpy(m_uploadbuffer,&h, sizeof(smb_header));
//    memcpy(m_uploadbuffer + sizeof(struct smb_header),
//           msg, 15);
    memcpy( m_uploadbuffer + sizeof(smb_header), &setup, sizeof(smb_setup));
    
    return smb_send(sizeof(struct smb_header)+ sizeof(struct smb_setup), 0);
    

}
int SMB::smb_send_and_recv(){
    void *msg = NULL;
    struct smb_negotiate_response *h;
    int bytes_read;

    bytes_read = smb_recv_message(&msg);
    if(bytes_read)
    {
        h = (struct smb_negotiate_response*)(msg);
    }
    else
    {
        return -1;
    }

    if(h)
    {
//        printWorkGroup(h);
        return 1;
    }
    
    return -1;
}


void SMB::printWorkGroup(struct smb_negotiate_response *h){
    
    if(h==nullptr)
        return;

    for(int i = 8 ; i < h->byte_count ;i++)
    {
        if(h->bytes+8+i)
            printf("%s",h->bytes+i);
        if( i == h->byte_count -1)
            printf("\n");
    }
    
    return;
}





