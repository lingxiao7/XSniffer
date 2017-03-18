// AdaptersDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "XSniffer.h"
#include "AdaptersDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "CommonDef.h"


// CAdaptersDlg 对话框

IMPLEMENT_DYNAMIC(CAdaptersDlg, CDialogEx)

CAdaptersDlg::CAdaptersDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_ADAPTERS, pParent)
{

}

CAdaptersDlg::CAdaptersDlg(CXSnifferDlg * pOwnerDlg, CWnd * pParent)
	: CDialogEx(IDD_DIALOG_ADAPTERS, pParent), m_pOwnerDlg(pOwnerDlg)
{
}

CAdaptersDlg::~CAdaptersDlg()
{
}

void CAdaptersDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_ADAPTERS, m_cAdapterList);
}


BEGIN_MESSAGE_MAP(CAdaptersDlg, CDialogEx)
//	ON_LBN_SELCHANGE(IDC_LIST_ADAPTERS, &CAdaptersDlg::OnLbnSelchangeListAdapters)
	ON_LBN_DBLCLK(IDC_LIST_ADAPTERS, &CAdaptersDlg::OnLbnDblclkListAdapters)
END_MESSAGE_MAP()


// CAdaptersDlg 消息处理程序


BOOL CAdaptersDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	pcap_if_t *d = NULL;
	pcap_if_t *alldevs = m_pOwnerDlg->GetAllDevs();
	USES_CONVERSION;

	for (d = alldevs; d != NULL; d = d->next)
	{
		WCHAR *pszName = A2W(d->name);
		WCHAR *pszDesc = A2W(d->description);
		WCHAR szInfo[ADAPTER_ADAPTER_NAME_LEN] = { 0 };

		wcscpy(szInfo, pszName);
		if (pszDesc != NULL)
		{
			wcscat(szInfo, _T(" "));
			wcscat(szInfo, pszDesc);
		}

		m_cAdapterList.InsertString(m_cAdapterList.GetCount(), szInfo);
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

void CAdaptersDlg::OnLbnDblclkListAdapters()
{
	// TODO: 在此添加控件通知处理程序代码
	CString strText;
	int nIndex = m_cAdapterList.GetCurSel();
	m_cAdapterList.GetText(nIndex, strText);

	m_pOwnerDlg->SetCurAdapter(nIndex);
	m_pOwnerDlg->SetCurAdapter(strText);

	CAdaptersDlg::OnOK();
}


//void CAdaptersDlg::OnLbnSelchangeListAdapters()
//{
//	// TODO: 在此添加控件通知处理程序代码
//}


/* 打印所有可用信息 */
void CAdaptersDlg::ifprint(pcap_if_t *d) {
	pcap_addr_t *a;
	char ip6str[128];


	USES_CONVERSION;
	/* 设备名(Name) */
	static WCHAR *pszName;
	pszName = A2W(d->name);

	/* 设备描述(Description) */
	static WCHAR *pszDesc;
	pszDesc = A2W(d->description);

	static WCHAR *szLoopbackAddr;
	/* Loopback Address*/
	wsprintf(szLoopbackAddr, _T("\tLoopback: %s\n"), (d->flags & PCAP_IF_LOOPBACK));

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;
		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS 12
char* CAdaptersDlg::iptos(u_long in) {
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char * CAdaptersDlg::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) {
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif // WIN32

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}



