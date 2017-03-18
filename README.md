# XSniffer

``XSniffer`` is a simple packet analyzer computer software using [WinPcap](https://www.winpcap.org) based on MFC DIALOG. 


## Dialog

``XSniffer`` is a MFC DIALOG BASED Program. So there's three dialogs.

### XSniffer Dialog

The main dialog. 
### CaptureFilter Dialog

To set filter using capture filter protocol.

#### CaptureFilter

| Protocol | bSrcIp | dwSrcIp | bDstIp | dwDstIp | bSrcPort | dwSrcPort | bDstPort | dwDstPort |
| ----- |:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|-----:|


```C++
struct CaptureFilter
{
    DWORD dwProtocol;       // 协议过滤规则
    BOOL  bSrcIp;           // 发送方IP过滤开关
    DWORD dwSrcIp;          // 过滤IP
    BOOL  bDstIp;           // 接收方IP过滤开关
    DWORD dwDstIp;          // 过滤IP

    BOOL  bSrcPort;         // 发送方端口过滤开关
    DWORD dwSrcPort;        // 端口过滤值
    BOOL  bDstPort;         // 接收方端口过滤开关
    DWORD dwDstPort;        // 端口过滤值
};
```


> Protocal in struct CaptureFilter
> 
>| IGMP | ICMP | ARP | UDP | TCP |
>|:----:|:-----:|:-----:|:-----:|:-----:|
>| 10 | 8 | 4 | 2 | 1 |


### Adapters Dialog

Double click to select adapture.

1. Retrieve the device list on the local machine.
2. Print the list.
3. Double click to set adapture in XSniffer.


## Threads

### ShowThread on ListView

The key task of this thread is add list view item using the global packets vector and show item.

The column header of the list view is that:

| INDEX | TIME | SRC | DST | LENGTH | DETAILS |
|:-----:|:----:|:-----:|:-----:|:-----:|:-----:|

The thread will convert the packets' data to format as correct column header. Refer to the protocol format(also see Protocal.h in project), the task is't difficult. 

### Capture Packets

The key task is open the adapture and set filter to store packets to he global packets vector.

1. Open the device.
2. Compile the filter.
3. Set the filter.
4. Pcap_next.
5. Free the device list.

## Protocal Format

### Ethernet

```C++
/*                                         Ethernet_II
|-------------------------------------------------------------------------------------------|
|        |         6         |       6         |  2  |............|            4            |
|Preamble|Destination Address|  Source Address |EType|FFFF(<=1500)|Frame Check Sequence(CRC)|
|-------------------------------------------------------------------------------------------|
*/
```

See also https://en.wikipedia.org/wiki/Ethernet

### ARP

```C++
/*     Internet Protocol(IPv4) over Ethernet ARP packet
|------------------------------------------------------------------|
| 0 |                    Hardware type(HTYPE)                      |
| 2 |                    Protocol type(PTYPE)                      |
| 4 | Hardware address length(HLEN) Protocol address length(PLEN)  |
| 6 |                       Operation(OPER)                        |
| 8 |                Sender hardware address(SHA)                  |
|14 |                Sender protocol address(SPA)                  |
|18 |                Target hardware address(THA)                  |
|24 |                Target protocol address(TPA)                  |
|------------------------------------------------------------------|
*/
```


See also https://en.wikipedia.org/wiki/Address_Resolution_Protocol

### IP

```C++
/*               IPv4 Header Format
|-----------------------------------------------------|
|Offsets|Octet| 4  | 4  |   8    |        16          |
| Octet | Bit |---------------------------------------|
|   0   |   0 |ver |len |  tos   |   Total length     |
|   4   |  32 |   identification |flg| Fragment offset|
|   8   |  64 |    TTL  | Proto  |   Header checksum  |
|  12   |  96 |           Source address              |
|  16   | 128 |         Destination address           |
|  20   | 160 |               Option                  |
|-----------------------------------------------------|
*/
```

See also https://en.wikipedia.org/wiki/Internet_Protocol.

### TCP

```C++
/*                                                         TCP Header
|--------------------------------------------------------------------------------------------------------------|
|Offsets|Octet| 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31|
| Octet | Bit |------------------------------------------------------------------------------------------------|
|   0   |   0 |                      Source port               |                Destination port               |
|   4   |  32 |                                         Sequence number                                        |
|   8   |  64 |                                 Acknowledgment number(if ACK set)                              |
|       |     |            |Reserved|N | C| E| U| A| P| R| S| F|                                               |
|  12   |  96 | Data offset|(0 0 0) |S | W| C| R| C| S| S| Y| I|                  Window Size                  |
|       |     |            |        |  | R| E| G| K| H| T| N| N|                                               |
|  16   | 128 |                       Checksum                 |            Urgent pointer(if URG set)         |
|  20   | 160 |            Options(if data offset > 5. Padded at the end with "0" bytes if necessary.)         |
|--------------------------------------------------------------------------------------------------------------|
*/
```

See also https://en.wikipedia.org/wiki/Transmission_Control_Protocol.

### UDP

```C++
/*                 UDP Header
|-----------------------------------------------------|
|Offsets|Octet|         16       |        16          |
| Octet | Bit |---------------------------------------|
|   0   |  0  |     Source port  |  Destination port  |
|   4   | 32  |  Datagram length |   Header checksum  |
|-----------------------------------------------------|
*/
```

See also https://en.wikipedia.org/wiki/User_Datagram_Protocol.

### ICMP

```C++
/*                ICMP Header
|-----------------------------------------------------|
|Offsets|Octet|    8    |    8   |         16         |
| Octet | Bit |---------------------------------------|
|   0   |  0  |   Type  |  Code  |   Header checksum  |
|-----------------------------------------------------|
*/
```

See also https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol.

### IGMP

```C++
/*                IGMP Header
|-----------------------------------------------------|
|Offsets|Octet|    8    |    8   |         16         |
| Octet | Bit |---------------------------------------|
|   0   |  0  |   Type  |  Code  |   Header checksum  |
|-----------------------------------------------------|
*/
```
See also https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol

