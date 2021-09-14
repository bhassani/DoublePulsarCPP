#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

unsigned char wannacry_Trans2_Request[] =
"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe"
"\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
"\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01"
"\x00\x0e\x00\x0d\x10\x00";

typedef uint16_t WORD;

//investigate the wierdness here
//wannacry sends (4178);
//but the packet says 4174
int main()
{
    //using uint16_t variable with htons
    uint16_t smblen;
    int totalSize = 70+12+4096;
    smblen = htons(70+12+4096);
    printf("Total size:  %d -> SMB packet len %x\n", totalSize, smblen);
    char wannacryPacket[4096];
    memcpy(wannacryPacket+2, &smblen, sizeof(uint16_t));
    printf("uint16 smblen -> copied to (Wannacry+2): %x\n",wannacryPacket[2]);
    printf("uint16 smblen -> copied to (Wannacry+3): %x\n",wannacryPacket[3]);
    
    //editing a char variable
    char smblength;
    smblength = 70+12+4096;
    memcpy(wannacryPacket+3, &smblength, 2);
    printf("char smbLen -> copied to (Wannacry+2): %x\n",wannacryPacket[2]);
    printf("char smbLen -> copied to (Wannacry+3): %x\n",wannacryPacket[3]);

    //editing a uint16_t variable with htons
    uint16_t trans2_code;
    trans2_code = htons(0x000e);
    printf("Session Type:  %X\n", trans2_code);
    
    printf("\nWhat the wannacry packet says:  \n");
    
    printf("Wannacry packet: + 2): %x\n",wannacry_Trans2_Request[2]);
    printf("Wannacry packet: + 3): %x\n",wannacry_Trans2_Request[3]);
    
    printf("Wannacry packet: + 39): TotalDataCount:  %d\n",wannacry_Trans2_Request[39]);
    printf("Wannacry packet: + 59): DataCount:%d\n",wannacry_Trans2_Request[59]);
    printf("Wannacry packet: + 69): Byte Count:%d\n",wannacry_Trans2_Request[69]);
    
    //update using memcpy
    uint16_t TotalDataCount = htons(4096);
    memcpy(wannacry_Trans2_Request, (char*)&TotalDataCount, 2);
    uint16_t DataCount = htons(4096);
    memcpy(wannacry_Trans2_Request, (char*)&DataCount, 2);
    uint16_t byteCount = htons(4096+13);
    memcpy(wannacry_Trans2_Request, (char*)&byteCount, 2);
    
    //update using the assignment
    *(WORD *)(wannacry_Trans2_Request+0x27)= htons(4096); //update Total Data Count
    *(WORD *)(wannacry_Trans2_Request+0x3b)= htons(4096); //update Data Count
    *(WORD *)(wannacry_Trans2_Request+0x45)= htons(4096+13); //update Byte Count

    return 0;
}
