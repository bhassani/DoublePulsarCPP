#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>

#pragma pack(1)

typedef struct
{
  unsigned char server_component[4];
  unsigned char command;
  unsigned char error_class;
  unsigned char reserved1;
  uint16_t error_code;
  uint8_t flags;
  uint16_t flags2;
  unsigned char reserved2[12];
  uint16_t tree_id;
  uint16_t proc_id;
  uint16_t user_id;
  uint16_t mpex_id;
}
__attribute__ ((packed)) smb_header;

typedef struct
{
  /* wct: word count */
  uint8_t wct;
  uint16_t total_param_cnt;
  uint16_t total_data_cnt;
  uint16_t max_param_cnt;
  uint16_t max_data_cnt;
  uint8_t max_setup_cnt;
  unsigned char reserved1;
  uint16_t flags;
  uint32_t timeout;
  uint16_t reserved2;
  uint16_t param_cnt;
  uint16_t param_offset;
  uint16_t data_cnt;
  uint16_t data_offset;
  uint8_t setup_count;
  uint8_t reserved3;
  /* bcc: byte count */
  uint16_t bcc;
}
__attribute__ ((packed)) transaction2_request;

#pragma pack(pop)

#define SESSION_MESSAGE 0x00
#define SMB_COM_TRANSACTION2 0x32

#define bswap16(x) \
  ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))


void
build_smb_header (smb_header * hdr, uint8_t command, uint8_t flags,
                  uint16_t flags2, uint16_t tree_id, uint16_t proc_id,
                  uint16_t user_id, uint16_t mpex_id)
{
  memset (hdr, 0, sizeof (smb_header));

  /* SMB Header MAGIC. */
  hdr->server_component[0] = 0xff;
  hdr->server_component[1] = 'S';
  hdr->server_component[2] = 'M';
  hdr->server_component[3] = 'B';

  hdr->command = command;

  hdr->flags = flags;
  hdr->flags2 = flags2;

  hdr->tree_id = tree_id;
  hdr->proc_id = proc_id;
  hdr->user_id = user_id;
  hdr->mpex_id = mpex_id;
}

void main()
{
    smb_header hdr;
    transaction2_request transaction;
    parameters params;
    uint16_t proc_id, tree_id, user_id;
    unsigned char *p;

    proc_id = (uint16_t) rand ();
    tree_id = ((smb_header *) (buffer + 4))->tree_id;
    user_id = ((smb_header *) (buffer + 4))->user_id;

    build_smb_header (&hdr, SMB_COM_TRANSACTION2, 0, 0, tree_id, proc_id,
                      user_id, 0);

    buffer[0] = SESSION_MESSAGE;
    buffer[1] = 0x0;

    memcpy (buffer + 4, &hdr, sizeof (smb_header));

    memset (&transaction, 0, sizeof (transaction_request));

    transaction.wct = 15;
    transaction.total_param_cnt = 12; /* Total lenght of parameters */
    transaction.param_cnt = 12; /* Lenght of parameter */

    p = buffer + 4 + sizeof (smb_header) + sizeof (transaction_request);
    transaction.param_offset = p - buffer - 4;

    
    memcpy (p, &params, sizeof (parameters));
    p += transaction.param_cnt;

    transaction.data_offset = p - buffer - 4;

    transaction.bcc =
    p - buffer - 4 - sizeof (smb_header) - sizeof (transaction_request);

    memcpy (buffer + 4 + sizeof (smb_header), &transaction,sizeof (transaction_request));

    /* Another byte count */
  *(uint16_t *) (buffer + 2) =
    bswap16 ((uint16_t)
             (sizeof (transaction_request) + sizeof (smb_header) +
              transaction.bcc));

  send(socket, buffer, sizeof (transaction_request) + sizeof (smb_header) + 4 + transaction.bcc);

}



