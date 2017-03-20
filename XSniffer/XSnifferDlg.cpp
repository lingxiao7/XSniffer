
// XSnifferDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "XSniffer.h"
#include "XSnifferDlg.h"
#include "afxdialogex.h"

#include "GlobalVar.h"
#include "Protocols.h"
#include <vector>
#include <iterator>

extern std::vector<PacketNode *> g_vcPackets;
extern WCHAR g_szIcmpType[42][40];
extern WCHAR g_szIgmpType[34][40];

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
//	afx_msg void OnAbout();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
//	ON_COMMAND(IDM_ABOUT, &CAboutDlg::OnAbout)
END_MESSAGE_MAP()


// CXSnifferDlg 对话框



CXSnifferDlg::CXSnifferDlg(CWnd* pParent /*=NULL*/)
	: m_pAllDevs(NULL), m_tCapThread(NULL), m_tShowThread(NULL),/* 线程置空，设备表置空 */
	CDialogEx(IDD_XSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CXSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PACKETS, m_cPacketsList);
	DDX_Control(pDX, IDC_TREE_PACKETS, m_cPacketsTree);
	DDX_Control(pDX, IDC_EDIT_PACKETS, m_cHexView);
	DDX_Control(pDX, IDC_STATIC_STATUS, m_cPacketNumBar);
	DDX_Control(pDX, IDC_STATIC_ADAPTER, m_cPacketAdapter);
}

BEGIN_MESSAGE_MAP(CXSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(IDM_FILE_QUIT, &CXSnifferDlg::OnFileQuit)
	ON_WM_CLOSE()
	ON_COMMAND(IDM_OPT_SELDEV, &CXSnifferDlg::OnOptSeldev)
	ON_COMMAND(IDM_ABOUT, &CXSnifferDlg::OnAbout)
	ON_COMMAND(IDM_OPT_SETCAPFILTER, &CXSnifferDlg::OnOptSetcapfilter)
	ON_COMMAND(IDM_OPT_STARTCAP, &CXSnifferDlg::OnOptStartcap)
	ON_COMMAND(IDM_OPT_STOPCAP, &CXSnifferDlg::OnOptStopcap)
	ON_COMMAND(ID_FILE_CLOSE, &CXSnifferDlg::OnFileClose)
	ON_NOTIFY(NM_CLICK, IDC_LIST_PACKETS, &CXSnifferDlg::OnClickListPackets)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE_PACKETS, &CXSnifferDlg::OnSelchangedTreePackets)
	ON_NOTIFY(TVN_DELETEITEM, IDC_TREE_PACKETS, &CXSnifferDlg::OnDeleteitemTreePackets)
END_MESSAGE_MAP()


// CXSnifferDlg 消息处理程序

BOOL CXSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	
	m_Menu.LoadMenu(IDR_MENU_MAIN);  //  IDR_MENU1为你加入的菜单的ID，在Resource视图的Menu文件夹下可以找到
	SetMenu(&m_Menu);

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	// 初始化控件以及WinPcap
	InitControls();
	InitWinPcap();

	// 预备g_vcPackets空间为 10MB
	g_vcPackets.reserve(10 * 1024 * 1024);

	// 初始数据包统计
	m_dwUdp = m_dwArp = m_dwIcmp = m_dwIgmp = m_dwRef = m_dwTcp = 0;

	// 初始显示线程
	SAFE_DELETE(m_tShowThread);
	m_tShowThread = new CShowThread(m_dwTcp, m_dwUdp,
		m_dwArp, m_dwIgmp, m_dwIcmp, this);
	m_tShowThread->ResumeThread();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CXSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CXSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CXSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// 初始化控件
BOOL CXSnifferDlg::InitControls()
{

	// 列表视图控件 属性设置
	DWORD dwStyle = m_cPacketsList.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;
	m_cPacketsList.SetExtendedStyle(dwStyle);

	// 列表视图控件 添加列头
	CString csHeadStr;
	DWORD dwCol = 0;

	// 加载列头字符串
	/* | 序号 | 时间 | 源主机地址 | 目的主机地址 | 协议类型 | 长度 | 详情 | */
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_NO);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 60);	// 第一列实际上不可以右对齐
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_TIME);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 120);	// 以下左对齐
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_SRCHOST);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 120);
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_DSTHOST);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 120);
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_PROTOCOL);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 50);
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_LENGTH);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 50);
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_DETAIL);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 400);


	// 十六进制控件
	m_cHexView.m_pData = NULL;
	m_cHexView.m_length = 0;
	m_cHexView.m_bpr = 16;		// 每行16个字节
	m_cHexView.m_lpp = 6;		// 每页06行数据

	m_cHexView.SetReadOnly();

	// 设置树形控件属性
	dwStyle = GetWindowLong(m_cPacketsTree.m_hWnd, GWL_STYLE);
	dwStyle |= TVS_LINESATROOT | TVS_HASBUTTONS | TVS_FULLROWSELECT;//| TVS_HASLINES;
	SetWindowLong(m_cPacketsTree.m_hWnd, GWL_STYLE, dwStyle);
	return 0;
}

// 初始化WinPcap
BOOL CXSnifferDlg::InitWinPcap()
{
	char errbuf[PCAP_ERRBUF_SIZE + 1]; // 错误信息
	USES_CONVERSION;

	/*printf("Enter the device you want to list:\n"
	"rpcap://              ==> lists interfaces in the local machine\n"
	"rpcap://hostname:port ==> lists interfaces in a remote machine\n"
	"                          (rpcapd daemon must be up and running\n"
	"                           and it must accept 'null' authentication)\n"
	"file://foldername     ==> lists all pcap files in the give folder\n\n"
	"Enter your choice: ");

	fgets(source, PCAP_ERRBUF_SIZE, stdin);
	source[PCAP_ERRBUF_SIZE] = '\0';*/

	/* 获得接口列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_pAllDevs, errbuf) == -1) {
		WCHAR *pszErrBuf = A2W(errbuf);
		MessageBox(pszErrBuf, _T("WinPcap初始化出错"), MB_ICONERROR);
		return FALSE;
	}

	/* 网卡 */
	m_nCurAdapter = -1;

	/* 过滤器 */
	ZeroMemory(&m_sCapFilter, sizeof(CaptureFilter)); // 不过滤
	m_sCapFilter.dwProtocol = 31; // 全部置位

	/* 工作状态 */
	m_bCurCapture = FALSE;

	return 0;
}

// 反初始化WinPcap
void CXSnifferDlg::UnInitWinPcap()
{
	if (m_pAllDevs != NULL) {
		pcap_freealldevs(m_pAllDevs);
	}
}


// 获取m_cPacketsList访问控制
CListCtrl* CXSnifferDlg::GetPacketListWnd()
{
	return &m_cPacketsList;
}

// 获取m_cPacketNumBar访问控制
CStatic* CXSnifferDlg::GetPacketNumBarWnd()
{
	return &m_cPacketNumBar;
}

void CXSnifferDlg::UpdatePackNum(DWORD dwTcp, DWORD dwUdp, DWORD dwArp, DWORD dwIgmp, DWORD dwIcmp)
{
	m_dwTcp = dwTcp;
	m_dwUdp = dwUdp;
	m_dwArp = dwArp;
	m_dwIgmp = dwIgmp;
	m_dwIcmp = dwIcmp;

	WCHAR szBuffer[64];
	wsprintf(szBuffer, _T("TCP %d UDP %d ARP %d IGMP %d ICMP %d"),
		m_dwTcp, m_dwUdp, m_dwArp, m_dwIgmp, m_dwIcmp);
	m_cPacketNumBar.SetWindowTextW(szBuffer);
}

pcap_if_t * CXSnifferDlg::GetAllDevs()
{
	return m_pAllDevs;
}


// 弹出选择网卡对话框
void CXSnifferDlg::OnOptSeldev()
{
	// TODO: 在此添加命令处理程序代码
	if (m_bCurCapture)
	{
		MessageBox(_T("已经处于抓包状态中，如需更改网络适配器请先停止本次抓包！"),
			_T("提示信息"), MB_ICONWARNING);
		return;
	}

	CAdaptersDlg dlg(this);
	dlg.DoModal();

	m_cPacketAdapter.SetWindowText(m_strCurAdapter);
}

// 弹出过滤器对话框
void CXSnifferDlg::OnOptSetcapfilter()
{
	// TODO: 在此添加命令处理程序代码
	if (m_bCurCapture)
	{
		MessageBox(_T("已经处于抓包状态中，如需更改网络适配器请先停止本次抓包！"),
			_T("提示信息"), MB_ICONWARNING);
		return;
	}

	CCapfilterDlg dlg(this, m_sCapFilter);
	dlg.DoModal();
}

void CXSnifferDlg::SetCurAdapter(int nIndex)
{
	m_nCurAdapter = nIndex;
}

void CXSnifferDlg::SetCurAdapter(CString strInfo)
{
	m_strCurAdapter = strInfo;
}

void CXSnifferDlg::SetCapFilter(CaptureFilter sCapFilter)
{
	m_sCapFilter = sCapFilter;
}

void CXSnifferDlg::OnOptStartcap()
{
	// TODO: 在此添加命令处理程序代码

	if (m_bCurCapture)
	{
		MessageBox(_T("已经处于抓包状态中，如需重新开始请先停止本次抓包！"),
			_T("提示信息"), MB_ICONWARNING);
		return;
	}

	int i = 0;
	pcap_if_t *d = m_pAllDevs;

	/* 跳转到选中的适配器 */
	while (i < m_nCurAdapter)
	{
		++i;
		d = d->next;
	}

	// 创建新线程开始抓包工作
	SAFE_DELETE(m_tCapThread);
	m_tCapThread = new CCapThread(d, m_sCapFilter);

	if (-1 != m_tCapThread->ResumeThread())
	{
		m_bCurCapture = TRUE;
	}
}


void CXSnifferDlg::OnOptStopcap()
{
	// TODO: 在此添加命令处理程序代码
	if (!m_bCurCapture)
	{
		MessageBox(_T("当前未处于抓包状态，本次操作忽略！"),
			_T("提示信息"), MB_ICONWARNING);
		return;
	}

	SAFE_DELETE(m_tCapThread);
	m_bCurCapture = FALSE;
}


void CXSnifferDlg::OnFileClose()
{
	// TODO: 在此添加命令处理程序代码
	SendMessage(WM_CLOSE, 0, 0);
}


void CXSnifferDlg::OnFileQuit()
{
	// TODO: 在此添加命令处理程序代码
	SendMessage(WM_CLOSE, 0, 0);
}

void CXSnifferDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	// 反初始化WinPcap
	UnInitWinPcap();
	// 释放分配的节点内存
	DeletePacket();
	CDialogEx::OnClose();
}

void CXSnifferDlg::OnAbout()
{
	// TODO: 在此添加命令处理程序代码
	CAboutDlg dlg;
	dlg.DoModal();
}



void CXSnifferDlg::OnClickListPackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	DWORD dwIndex = pNMItemActivate->iItem;
	DWORD dwSize = g_vcPackets.size();

	if (dwIndex >= 0 && dwIndex < dwSize) {
		PacketNode *pNode = g_vcPackets[dwIndex];

		// 树形控件内容显示
		UpdateTreeViewData(dwIndex);

		// BugFix: 十六进制控件的垂直滚动条有点问题
		// 连续调用两次才正常
		m_cHexView.SetData(pNode->pData, pNode->pHeader->caplen);
		m_cHexView.SetData(pNode->pData, pNode->pHeader->caplen);
		m_cHexView.Invalidate();
	}

	*pResult = 0;
}


void CXSnifferDlg::OnSelchangedTreePackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	HTREEITEM hNode = m_cPacketsTree.GetSelectedItem();
	if (hNode == NULL) return;

	TreeNodeData *pTnd = (TreeNodeData *)(m_cPacketsTree.GetItemData(hNode));
	m_cHexView.SetSel(pTnd->dwStartPos, pTnd->dwEndPos);

	*pResult = 0;
}


void CXSnifferDlg::OnDeleteitemTreePackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	if (pNMTreeView->itemOld.lParam != NULL)
	{
		free((TreeNodeData *)(pNMTreeView->itemOld.lParam));
	}

	*pResult = 0;
}


// 更新TreeView数据
void CXSnifferDlg::UpdateTreeViewData(DWORD dwIndex)
{
	PacketNode *pNode = g_vcPackets[dwIndex];

	EthernetHeader *pEthHeader = (EthernetHeader *)pNode->pData;
	static TCHAR szSrcMac[64] = { 0 };
	static TCHAR szDstMac[64] = { 0 };
	static TCHAR szMacFmt[64] = _T("%s: %02X-%02X-%02X-%02X-%02X-%02X");
	static TCHAR szProtocolType[32] = { 0 };

	m_cPacketsTree.DeleteAllItems();

	wsprintf(szSrcMac, szMacFmt, _T("Source"),
		pEthHeader->sSrcMac.byte1, pEthHeader->sSrcMac.byte2,
		pEthHeader->sSrcMac.byte3, pEthHeader->sSrcMac.byte4,
		pEthHeader->sSrcMac.byte5, pEthHeader->sSrcMac.byte6);

	wsprintf(szDstMac, szMacFmt, _T("Destination"),
		pEthHeader->sDstMac.byte1, pEthHeader->sDstMac.byte2,
		pEthHeader->sDstMac.byte3, pEthHeader->sDstMac.byte4,
		pEthHeader->sDstMac.byte5, pEthHeader->sDstMac.byte6);

	// [节点] Ethernet头部整体
	HTREEITEM hEthernet = m_cPacketsTree.InsertItem(_T("Ethernet"));
	TreeNodeData *pTndEthernet = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthernet->dwStartPos = 0;
	pTndEthernet->dwEndPos = pTndEthernet->dwStartPos + sizeof(EthernetHeader);
	m_cPacketsTree.SetItemData(hEthernet, (DWORD)pTndEthernet);

	// [节点] DstMac头部整体
	HTREEITEM hEthDstMac = m_cPacketsTree.InsertItem(szDstMac, hEthernet);
	TreeNodeData *pTndEthDstMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthDstMac->dwStartPos = 0;
	pTndEthDstMac->dwEndPos = pTndEthDstMac->dwStartPos + sizeof(MacAddr);
	m_cPacketsTree.SetItemData(hEthDstMac, (DWORD)pTndEthDstMac);

	// [节点] SrcMac头部整体
	HTREEITEM hEthSrcMac = m_cPacketsTree.InsertItem(szSrcMac, hEthernet);
	TreeNodeData *pTndEthSrcMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthSrcMac->dwStartPos = pTndEthDstMac->dwEndPos;
	pTndEthSrcMac->dwEndPos = pTndEthSrcMac->dwStartPos + sizeof(MacAddr);
	m_cPacketsTree.SetItemData(hEthSrcMac, (DWORD)pTndEthSrcMac);

	// 协议类型附加数据
	TreeNodeData *pTndEthProtoType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthProtoType->dwStartPos = pTndEthSrcMac->dwEndPos;
	pTndEthProtoType->dwEndPos = pTndEthProtoType->dwStartPos + 2;

	// ==========================================================================
	// ARP数据包解析
	// ==========================================================================
	if (ntohs(pEthHeader->nEthType) == 0x0806)	// ARP
	{
		static TCHAR szSrcIp[128];
		static TCHAR szSrcMac[128];
		static TCHAR szDstIp[128];
		static TCHAR szDstMac[128];
		static TCHAR szHardwareType[32];
		// static TCHAR szProtocolType[32];
		static TCHAR szHardwareSize[32];
		static TCHAR szProtocolSize[32];
		static TCHAR szOpcode[32];
		static TCHAR szOpString[3][16] = { _T("Not defined"), _T("Request"), _T("Response") };

		// ARP头部格式解析
		ArpHeader *pArpHdr = (ArpHeader *)(pNode->pData + sizeof(EthernetHeader));

		// 发送方MAC地址和IP地址
		wsprintf(szSrcMac, _T("Sender MAC address: %02X-%02X-%02X-%02X-%02X-%02X"),
			pArpHdr->sSrcMac.byte1, pArpHdr->sSrcMac.byte2, pArpHdr->sSrcMac.byte3,
			pArpHdr->sSrcMac.byte4, pArpHdr->sSrcMac.byte5, pArpHdr->sSrcMac.byte6);
		wsprintf(szSrcIp, _T("Sender IP address: %d.%d.%d.%d"), pArpHdr->sSrcIp.byte1,
			pArpHdr->sSrcIp.byte2, pArpHdr->sSrcIp.byte3, pArpHdr->sSrcIp.byte4);

		// 接收方MAC地址和IP地址
		wsprintf(szDstMac, _T("Target MAC address: %02X-%02X-%02X-%02X-%02X-%02X"),
			pArpHdr->sDstMac.byte1, pArpHdr->sDstMac.byte2, pArpHdr->sDstMac.byte3,
			pArpHdr->sDstMac.byte4, pArpHdr->sDstMac.byte5, pArpHdr->sDstMac.byte6);
		wsprintf(szSrcIp, _T("Sender IP address: %d.%d.%d.%d"), pArpHdr->sDstIp.byte1,
			pArpHdr->sDstIp.byte2, pArpHdr->sDstIp.byte3, pArpHdr->sDstIp.byte4);

		// ARP包类型
		unsigned short uOpcode = ntohs(pArpHdr->nOpCode);
		if (uOpcode > 2) uOpcode = 0; // 未定义

									  // [节点] Ethernet协议字段: 协议类型
		wcscpy(szProtocolType, _T("Type: ARP (0x0806)"));
		HTREEITEM hEthProtoType = m_cPacketsTree.InsertItem(szProtocolType, hEthernet);
		m_cPacketsTree.SetItemData(hEthProtoType, (DWORD)pTndEthProtoType);

		// [节点] ARP头部整体
		HTREEITEM hArp = m_cPacketsTree.InsertItem(_T("Address Resolution Protocol"));
		TreeNodeData *pTndArp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndArp->dwStartPos = pTndEthProtoType->dwEndPos;
		pTndArp->dwEndPos = pTndArp->dwStartPos + sizeof(ArpHeader);
		m_cPacketsTree.SetItemData(hArp, (DWORD)pTndArp);

		// [节点] 硬件类型
		wsprintf(szHardwareType, _T("Hardware type: 0x%04X"),
			ntohs(pArpHdr->nHardType));
		HTREEITEM hHardwareType = m_cPacketsTree.InsertItem(szHardwareType, hArp);
		TreeNodeData *pTndHardwareType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndHardwareType->dwStartPos = pTndArp->dwStartPos;
		pTndHardwareType->dwEndPos = pTndHardwareType->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hHardwareType, (DWORD)pTndHardwareType);

		// [节点] 协议类型
		wsprintf(szProtocolType, _T("Protocol type: 0x%04X"),
			ntohs(pArpHdr->nProtoType));
		HTREEITEM hProtocolType = m_cPacketsTree.InsertItem(szProtocolType, hArp);
		TreeNodeData *pTndProtocolType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndProtocolType->dwStartPos = pTndHardwareType->dwEndPos;
		pTndProtocolType->dwEndPos = pTndProtocolType->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hProtocolType, (DWORD)pTndProtocolType);

		// [节点] 硬件大小
		wsprintf(szHardwareSize, _T("Hardware size: 0x%02X"),
			pArpHdr->nMacLen);
		HTREEITEM hHardwareSize = m_cPacketsTree.InsertItem(szHardwareSize, hArp);
		TreeNodeData *pTndHardwareSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndHardwareSize->dwStartPos = pTndProtocolType->dwEndPos;
		pTndHardwareSize->dwEndPos = pTndHardwareSize->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hHardwareSize, (DWORD)pTndHardwareSize);

		// [节点] 协议大小
		wsprintf(szProtocolSize, _T("Protocol size: 0x%02X"),
			pArpHdr->nProtoLen);
		HTREEITEM hProtocolSize = m_cPacketsTree.InsertItem(szProtocolSize, hArp);
		TreeNodeData *pTndProtocolSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndProtocolSize->dwStartPos = pTndHardwareSize->dwEndPos;
		pTndProtocolSize->dwEndPos = pTndProtocolSize->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hProtocolSize, (DWORD)pTndProtocolSize);

		// [节点] 操作码
		wsprintf(szOpcode, _T("Opcode: 0x%04X (%s)"),
			ntohs(pArpHdr->nOpCode), szOpString[uOpcode]);
		HTREEITEM hOpcode = m_cPacketsTree.InsertItem(szOpcode, hArp);
		TreeNodeData *pTndOpcode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndOpcode->dwStartPos = pTndProtocolSize->dwEndPos;
		pTndOpcode->dwEndPos = pTndOpcode->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hOpcode, (DWORD)pTndOpcode);

		// [节点] 发送方MAC地址
		HTREEITEM hSrcMac = m_cPacketsTree.InsertItem(szSrcMac, hArp);
		TreeNodeData *pTndSrcMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcMac->dwStartPos = pTndOpcode->dwEndPos;
		pTndSrcMac->dwEndPos = pTndSrcMac->dwStartPos + sizeof(MacAddr);
		m_cPacketsTree.SetItemData(hSrcMac, (DWORD)pTndSrcMac);

		// [节点] 发送方IP地址
		HTREEITEM hSrcIp = m_cPacketsTree.InsertItem(szSrcIp, hArp);
		TreeNodeData *pTndSrcIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcIp->dwStartPos = pTndSrcMac->dwEndPos;
		pTndSrcIp->dwEndPos = pTndSrcIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hSrcIp, (DWORD)pTndSrcIp);

		// [节点] 接收方MAC地址
		HTREEITEM hDstMac = m_cPacketsTree.InsertItem(szDstMac, hArp);
		TreeNodeData *pTndDstMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstMac->dwStartPos = pTndSrcIp->dwEndPos;
		pTndDstMac->dwEndPos = pTndDstMac->dwStartPos + sizeof(MacAddr);
		m_cPacketsTree.SetItemData(hDstMac, (DWORD)pTndDstMac);

		// [节点] 接收方IP地址
		HTREEITEM hDstIp = m_cPacketsTree.InsertItem(szDstIp, hArp);
		TreeNodeData *pTndDstIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstIp->dwStartPos = pTndDstMac->dwEndPos;
		pTndDstIp->dwEndPos = pTndDstIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hDstIp, (DWORD)pTndDstIp);
	}
	// ==========================================================================
	// IP数据包解析
	// ==========================================================================
	else if (ntohs(pEthHeader->nEthType) == 0x0800)
	{
		IpHeader *pIpHdr = (IpHeader *)(pNode->pData + sizeof(EthernetHeader));
		DWORD dwIpHdrLen = (pIpHdr->nVerHl & 0xf) * 4;	// 一定要乘以4

													// [节点] Ethernet协议字段: 协议类型
		wcscpy(szProtocolType, _T("Type: IP (0x0800)"));
		HTREEITEM hEthProtoType = m_cPacketsTree.InsertItem(szProtocolType, hEthernet);
		m_cPacketsTree.SetItemData(hEthProtoType, (DWORD)pTndEthProtoType);

		// [节点] IP头部整体
		HTREEITEM hIp = m_cPacketsTree.InsertItem(_T("Internet Protocol"));
		TreeNodeData *pTndIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIp->dwStartPos = pTndEthProtoType->dwEndPos;
		pTndIp->dwEndPos = pTndIp->dwStartPos + sizeof(IpHeader);
		m_cPacketsTree.SetItemData(hIp, (DWORD)pTndIp);

		// [节点] IP版本
		static WCHAR szIpVer[16];
		wsprintf(szIpVer, _T("Version: %u"), (pIpHdr->nVerHl & 0xf0));
		HTREEITEM hIpVer = m_cPacketsTree.InsertItem(szIpVer, hIp);
		TreeNodeData *pTndIpVer = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpVer->dwStartPos = pTndIp->dwStartPos;
		pTndIpVer->dwEndPos = pTndIpVer->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpVer, (DWORD)pTndIpVer);

		// [节点] IP 头部长度
		static WCHAR szIpHdrLen[32];
		wsprintf(szIpHdrLen, _T("Header length: %u bytes"), dwIpHdrLen);
		HTREEITEM hIpHdrLen = m_cPacketsTree.InsertItem(szIpHdrLen, hIp);
		TreeNodeData *pTndIpHdrLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpHdrLen->dwStartPos = pTndIp->dwStartPos;
		pTndIpHdrLen->dwEndPos = pTndIpHdrLen->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpHdrLen, (DWORD)pTndIpHdrLen);

		// [节点] IP 服务类型
		static WCHAR szIpTos[64];
		wsprintf(szIpTos, _T("Differentiated Services Field: 0x%02X"), pIpHdr->nTos);
		HTREEITEM hIpTos = m_cPacketsTree.InsertItem(szIpTos, hIp);
		TreeNodeData *pTndIpTos = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpTos->dwStartPos = pTndIpHdrLen->dwEndPos;
		pTndIpTos->dwEndPos = pTndIpTos->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpTos, (DWORD)pTndIpTos);

		// [节点] IP 总长度
		static WCHAR szIpTotalLen[64];
		wsprintf(szIpTotalLen, _T("Total length: 0x%04X"), ntohs(pIpHdr->nTotalLen));
		HTREEITEM hIpTotalLen = m_cPacketsTree.InsertItem(szIpTotalLen, hIp);
		TreeNodeData *pTndTotalLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndTotalLen->dwStartPos = pTndIpTos->dwEndPos;
		pTndTotalLen->dwEndPos = pTndTotalLen->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpTotalLen, (DWORD)pTndTotalLen);

		// [节点] IP 标识
		static WCHAR szIpIdent[64];
		wsprintf(szIpIdent, _T("Identification: 0x%04X"), ntohs(pIpHdr->nIdent));
		HTREEITEM hIpIdent = m_cPacketsTree.InsertItem(szIpIdent, hIp);
		TreeNodeData *pTndIdent = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIdent->dwStartPos = pTndTotalLen->dwEndPos;
		pTndIdent->dwEndPos = pTndIdent->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpIdent, (DWORD)pTndIdent);

		// [节点] IP 分片偏移
		static WCHAR szIpFragOff[64];
		wsprintf(szIpFragOff, _T("Fragment offset: %u"), ntohs(pIpHdr->nFragOff));
		HTREEITEM hIpFragOff = m_cPacketsTree.InsertItem(szIpFragOff, hIp);
		TreeNodeData *pTndFragOff = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndFragOff->dwStartPos = pTndIdent->dwEndPos;
		pTndFragOff->dwEndPos = pTndFragOff->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpFragOff, (DWORD)pTndFragOff);

		// [节点] IP TTL
		static WCHAR szIpTtl[64];
		wsprintf(szIpTtl, _T("Time to live: %u"), pIpHdr->nTtl);
		HTREEITEM hIpTtl = m_cPacketsTree.InsertItem(szIpTtl, hIp);
		TreeNodeData *pTndTtl = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndTtl->dwStartPos = pTndFragOff->dwEndPos;
		pTndTtl->dwEndPos = pTndTtl->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpTtl, (DWORD)pTndTtl);

		// [节点] IP 协议类型
		static WCHAR szIpProto[64];
		static WCHAR szIpProtoType[16] = { _T("Unknown") };
		if (pIpHdr->nProtocol == 1) wcscpy(szIpProtoType, _T("ICMP"));
		else if (pIpHdr->nProtocol == 2) wcscpy(szIpProtoType, _T("IGMP"));
		else if (pIpHdr->nProtocol == 6) wcscpy(szIpProtoType, _T("TCP"));
		else if (pIpHdr->nProtocol == 17) wcscpy(szIpProtoType, _T("UDP"));
		wsprintf(szIpProto, _T("Protocol: %s (%u)"), szIpProtoType, pIpHdr->nProtocol);
		HTREEITEM hIpProto = m_cPacketsTree.InsertItem(szIpProto, hIp);
		TreeNodeData *pTndProto = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndProto->dwStartPos = pTndTtl->dwEndPos;
		pTndProto->dwEndPos = pTndProto->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpProto, (DWORD)pTndProto);

		// [节点] IP 头部校验
		static WCHAR szIpCrc[64];
		wsprintf(szIpCrc, _T("Header checksum: 0x%04X"), ntohs(pIpHdr->nCrc));
		HTREEITEM hIpCrc = m_cPacketsTree.InsertItem(szIpCrc, hIp);
		TreeNodeData *pTndCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndCrc->dwStartPos = pTndProto->dwEndPos;
		pTndCrc->dwEndPos = pTndCrc->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpCrc, (DWORD)pTndCrc);

		// [节点] IP 发送方IP地址
		static WCHAR szIpSrcIp[64];
		wsprintf(szIpSrcIp, _T("Source: %d.%d.%d.%d"), pIpHdr->sSrcIp.byte1,
			pIpHdr->sSrcIp.byte2, pIpHdr->sSrcIp.byte3, pIpHdr->sSrcIp.byte4);
		HTREEITEM hIpSrcIp = m_cPacketsTree.InsertItem(szIpSrcIp, hIp);
		TreeNodeData *pTndSrcIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcIp->dwStartPos = pTndCrc->dwEndPos;
		pTndSrcIp->dwEndPos = pTndSrcIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hIpSrcIp, (DWORD)pTndSrcIp);

		// [节点] IP 接收方IP地址
		static WCHAR szIpDstIp[64];
		wsprintf(szIpDstIp, _T("Source: %d.%d.%d.%d"), pIpHdr->sDstIp.byte1,
			pIpHdr->sDstIp.byte2, pIpHdr->sDstIp.byte3, pIpHdr->sDstIp.byte4);
		HTREEITEM hIpDstIp = m_cPacketsTree.InsertItem(szIpDstIp, hIp);
		TreeNodeData *pTndDstIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstIp->dwStartPos = pTndSrcIp->dwEndPos;
		pTndDstIp->dwEndPos = pTndDstIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hIpDstIp, (DWORD)pTndDstIp);

		// ======================================================================
		// ICMP数据包解析
		// ======================================================================
		if (pIpHdr->nProtocol == 1)
		{
			// [节点] ICMP头部整体
			HTREEITEM hIcmp = m_cPacketsTree.InsertItem(_T("Internet Control Message Protocol"));
			TreeNodeData *pTndIcmp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndIcmp->dwEndPos = pNode->pHeader->caplen;
			m_cPacketsTree.SetItemData(hIcmp, (DWORD)pTndIcmp);

			// [节点] ICMP 类型
			static WCHAR szIcmpType[128];
			IcmpHeader *pIcmpHdr = (IcmpHeader *)((BYTE *)pIpHdr + dwIpHdrLen);
			if (pIcmpHdr->nType >= 0 && pIcmpHdr->nType <= ICMP_TYPE_VALUE_MAX)
			{
				wsprintf(szIcmpType, _T("Type: %d (%s)"),
					pIcmpHdr->nType,
					g_szIcmpType[pIcmpHdr->nType]);
			}
			else
			{
				wsprintf(szIcmpType, _T("Type: %d (Type not defined)"),
					pIcmpHdr->nType);
			}
			HTREEITEM hIcmpType = m_cPacketsTree.InsertItem(szIcmpType, hIcmp);
			TreeNodeData *pTndIcmpType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpType->dwStartPos = pTndIcmp->dwStartPos;
			pTndIcmpType->dwEndPos = pTndIcmpType->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIcmpType, (DWORD)pTndIcmpType);

			// [节点] ICMP Code
			static WCHAR szIcmpCode[16];
			wsprintf(szIcmpCode, _T("Code: %d"), pIcmpHdr->nCode);
			HTREEITEM hIcmpCode = m_cPacketsTree.InsertItem(szIcmpCode, hIcmp);
			TreeNodeData *pTndIcmpCode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCode->dwStartPos = pTndIcmpType->dwEndPos;
			pTndIcmpCode->dwEndPos = pTndIcmpCode->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIcmpCode, (DWORD)pTndIcmpCode);

			// [节点] ICMP 校验
			static WCHAR szIcmpCrc[32];
			wsprintf(szIcmpCrc, _T("Checksum: 0x%04X"), ntohs(pIcmpHdr->nCheckSum));
			HTREEITEM hIcmpCrc = m_cPacketsTree.InsertItem(szIcmpCrc, hIcmp);
			TreeNodeData *pTndIcmpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCrc->dwStartPos = pTndIcmpCode->dwEndPos;
			pTndIcmpCrc->dwEndPos = pTndIcmpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hIcmpCrc, (DWORD)pTndIcmpCrc);
		}
		// ======================================================================
		// IGMP数据包解析
		// ======================================================================
		else if (pIpHdr->nProtocol == 2)
		{
			// [节点] IGMP头部整体
			HTREEITEM hIgmp = m_cPacketsTree.InsertItem(_T("Internet Group Management Protocol"));
			TreeNodeData *pTndIgmp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIgmp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndIgmp->dwEndPos = pNode->pHeader->caplen;
			m_cPacketsTree.SetItemData(hIgmp, (DWORD)pTndIgmp);

			// [节点] IGMP 类型
			static WCHAR szIgmpType[128];
			IgmpHeader *pIgmpHdr = (IgmpHeader *)((BYTE *)pIpHdr + dwIpHdrLen);
			if (pIgmpHdr->nType >= 0 && pIgmpHdr->nType <= IGMP_TYPE_VALUE_MAX)
			{
				wsprintf(szIgmpType, _T("Type: %d (%s)"),
					pIgmpHdr->nType,
					g_szIgmpType[pIgmpHdr->nType]);
			}
			else
			{
				wsprintf(szIgmpType, _T("Type: %d (Type not defined)"),
					pIgmpHdr->nType);
			}
			HTREEITEM hIgmpType = m_cPacketsTree.InsertItem(szIgmpType, hIgmp);
			TreeNodeData *pTndIgmpType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIgmpType->dwStartPos = pTndIgmp->dwStartPos;
			pTndIgmpType->dwEndPos = pTndIgmpType->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIgmpType, (DWORD)pTndIgmpType);

			// [节点] IGMP Code
			static WCHAR szIgmpCode[16];
			wsprintf(szIgmpCode, _T("Code: %d"), pIgmpHdr->nCode);
			HTREEITEM hIgmpCode = m_cPacketsTree.InsertItem(szIgmpCode, hIgmp);
			TreeNodeData *pTndIgmpCode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIgmpCode->dwStartPos = pTndIgmpType->dwEndPos;
			pTndIgmpCode->dwEndPos = pTndIgmpCode->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIgmpCode, (DWORD)pTndIgmpCode);

			// [节点] IGMP 校验
			static WCHAR szIgmpCrc[32];
			wsprintf(szIgmpCrc, _T("Checksum: 0x%04X"), ntohs(pIgmpHdr->nCheckSum));
			HTREEITEM hIgmpCrc = m_cPacketsTree.InsertItem(szIgmpCrc, hIgmp);
			TreeNodeData *pTndIcmpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCrc->dwStartPos = pTndIgmpCode->dwEndPos;
			pTndIcmpCrc->dwEndPos = pTndIcmpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hIgmpCrc, (DWORD)hIgmpCrc);
		}
		// ======================================================================
		// TCP数据包解析
		// ======================================================================
		else if (pIpHdr->nProtocol == 6)
		{
			TcpHeader *pTcpHdr = (TcpHeader *)((BYTE*)pIpHdr + dwIpHdrLen);

			// [节点] TCP头部整体
			HTREEITEM hTcp = m_cPacketsTree.InsertItem(_T("Transmission Control Protocol"));
			TreeNodeData *pTndTcp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndTcp->dwEndPos = pTndTcp->dwStartPos + sizeof(TcpHeader);
			m_cPacketsTree.SetItemData(hTcp, (DWORD)pTndTcp);

			// [节点] TCP 发送方端口
			static WCHAR szTcpSrcPort[32];
			wsprintf(szTcpSrcPort, _T("Source port: %d"), ntohs(pTcpHdr->nSrcPort));
			HTREEITEM hTcpSrcPort = m_cPacketsTree.InsertItem(szTcpSrcPort, hTcp);
			TreeNodeData *pTndTcpSrcPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpSrcPort->dwStartPos = pTndTcp->dwStartPos;
			pTndTcpSrcPort->dwEndPos = pTndTcpSrcPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpSrcPort, (DWORD)pTndTcpSrcPort);

			// [节点] TCP 接收方端口
			static WCHAR szTcpDstPort[32];
			wsprintf(szTcpDstPort, _T("Destination port: %d"), ntohs(pTcpHdr->nDstPort));
			HTREEITEM hTcpDstPort = m_cPacketsTree.InsertItem(szTcpDstPort, hTcp);
			TreeNodeData *pTndTcpDstPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpDstPort->dwStartPos = pTndTcpSrcPort->dwEndPos;
			pTndTcpDstPort->dwEndPos = pTndTcpDstPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpDstPort, (DWORD)pTndTcpDstPort);

			// [节点] TCP SeqNum
			static WCHAR szTcpSeqNum[32];
			wsprintf(szTcpSeqNum, _T("SeqNum: %lu"), ntohl(pTcpHdr->nSeqNum));
			HTREEITEM hTcpSeqNum = m_cPacketsTree.InsertItem(szTcpSeqNum, hTcp);
			TreeNodeData *pTndTcpSeqNum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpSeqNum->dwStartPos = pTndTcpDstPort->dwEndPos;
			pTndTcpSeqNum->dwEndPos = pTndTcpSeqNum->dwStartPos + sizeof(unsigned long);
			m_cPacketsTree.SetItemData(hTcpSeqNum, (DWORD)pTndTcpSeqNum);

			// [节点] TCP AckNum
			static WCHAR szTcpAckNum[32];
			wsprintf(szTcpAckNum, _T("AckNum: %lu"), ntohl(pTcpHdr->nAckNum));
			HTREEITEM hTcpAckNum = m_cPacketsTree.InsertItem(szTcpAckNum, hTcp);
			TreeNodeData *pTndTcpAckNum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpAckNum->dwStartPos = pTndTcpSeqNum->dwEndPos;
			pTndTcpAckNum->dwEndPos = pTndTcpAckNum->dwStartPos + sizeof(unsigned long);
			m_cPacketsTree.SetItemData(hTcpAckNum, (DWORD)pTndTcpAckNum);

			// [节点] TCP HeaderLen
			static WCHAR szTcpHeaderLen[32];
			wsprintf(szTcpHeaderLen, _T("Header length: %d"), pTcpHdr->nHeaderLen);
			HTREEITEM hTcpHeaderLen = m_cPacketsTree.InsertItem(szTcpHeaderLen, hTcp);
			TreeNodeData *pTndTcpHeaderLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpHeaderLen->dwStartPos = pTndTcpAckNum->dwEndPos;
			pTndTcpHeaderLen->dwEndPos = pTndTcpHeaderLen->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hTcpHeaderLen, (DWORD)pTndTcpHeaderLen);

			// [节点] TCP Flags
			WCHAR szFlags[32] = { 0 };
			if (pTcpHdr->bFin) wcscat(szFlags, _T("FIN,"));
			if (pTcpHdr->bSyn) wcscat(szFlags, _T("SYN,"));
			if (pTcpHdr->bRst) wcscat(szFlags, _T("RST,"));
			if (pTcpHdr->bPsh) wcscat(szFlags, _T("PSH,"));
			if (pTcpHdr->bAck) wcscat(szFlags, _T("ACK,"));
			if (pTcpHdr->bUgr) wcscat(szFlags, _T("UGR,"));
			if (wcslen(szFlags) != 0)
			{
				szFlags[wcslen(szFlags) - 1] = _T('\0');
			}
			static WCHAR szTcpFlags[32];
			wsprintf(szTcpFlags, _T("Flags: %s"), szFlags);
			HTREEITEM hTcpFlags = m_cPacketsTree.InsertItem(szTcpFlags, hTcp);
			TreeNodeData *pTndTcpFlags = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpFlags->dwStartPos = pTndTcpHeaderLen->dwEndPos;
			pTndTcpFlags->dwEndPos = pTndTcpFlags->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hTcpFlags, (DWORD)pTndTcpFlags);

			// [节点] TCP WinSize
			static WCHAR szTcpWinSize[32];
			wsprintf(szTcpWinSize, _T("Window size value: %u"), ntohl(pTcpHdr->nWinSize));
			HTREEITEM hTcpWinSize = m_cPacketsTree.InsertItem(szTcpWinSize, hTcp);
			TreeNodeData *pTndTcpWinSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpWinSize->dwStartPos = pTndTcpFlags->dwEndPos;
			pTndTcpWinSize->dwEndPos = pTndTcpWinSize->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpWinSize, (DWORD)pTndTcpWinSize);

			// [节点] TCP CheckSum
			static WCHAR szTcpCheckSum[32];
			wsprintf(szTcpCheckSum, _T("Checksum: 0x%02X"), ntohl(pTcpHdr->nCheckSum));
			HTREEITEM hTcpCheckSum = m_cPacketsTree.InsertItem(szTcpCheckSum, hTcp);
			TreeNodeData *pTndTcpCheckSum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpCheckSum->dwStartPos = pTndTcpWinSize->dwEndPos;
			pTndTcpCheckSum->dwEndPos = pTndTcpCheckSum->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpCheckSum, (DWORD)pTndTcpCheckSum);

			// [节点] TCP UrgPtr
			static WCHAR szTcpUrgPtr[32];
			wsprintf(szTcpUrgPtr, _T("UrgPtr: 0x%02X"), ntohl(pTcpHdr->nUrgPtr));
			HTREEITEM hTcpUrgPtr = m_cPacketsTree.InsertItem(szTcpUrgPtr, hTcp);
			TreeNodeData *pTndTcpUrgPtr = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpUrgPtr->dwStartPos = pTndTcpCheckSum->dwEndPos;
			pTndTcpUrgPtr->dwEndPos = pTndTcpUrgPtr->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpUrgPtr, (DWORD)pTndTcpUrgPtr);

			// [节点] TCP 数据
			if (pTndTcpUrgPtr->dwEndPos < pNode->pHeader->caplen)
			{
				HTREEITEM hTcpData = m_cPacketsTree.InsertItem(_T("Data"), hTcp);
				TreeNodeData *pTndTcpData = (TreeNodeData *)malloc(sizeof(TreeNodeData));
				pTndTcpData->dwStartPos = pTndTcpUrgPtr->dwEndPos;
				pTndTcpData->dwEndPos = pNode->pHeader->caplen;
				m_cPacketsTree.SetItemData(hTcpData, (DWORD)pTndTcpData);
			}
		}
		// ======================================================================
		// UDP数据包解析
		// ======================================================================
		else if (pIpHdr->nProtocol == 17)
		{
			UdpHeader *pUdpHdr = (UdpHeader *)((BYTE*)pIpHdr + dwIpHdrLen);
			// [节点] UDP头部整体
			HTREEITEM hUdp = m_cPacketsTree.InsertItem(_T("User Datagram Protocol"));
			TreeNodeData *pTndUdp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndUdp->dwEndPos = pTndUdp->dwStartPos + sizeof(UdpHeader);
			m_cPacketsTree.SetItemData(hUdp, (DWORD)pTndUdp);

			// [节点] UDP 发送方端口
			static WCHAR szUdpSrcPort[32];
			wsprintf(szUdpSrcPort, _T("Source port: %d"), ntohs(pUdpHdr->nSrcPort));
			HTREEITEM hUdpSrcPort = m_cPacketsTree.InsertItem(szUdpSrcPort, hUdp);
			TreeNodeData *pTndUdpSrcPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpSrcPort->dwStartPos = pTndUdp->dwStartPos;
			pTndUdpSrcPort->dwEndPos = pTndUdpSrcPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpSrcPort, (DWORD)pTndUdpSrcPort);

			// [节点] UDP 接收方端口
			static WCHAR szUdpDstPort[32];
			wsprintf(szUdpDstPort, _T("Destination port: %d"), ntohs(pUdpHdr->nDstPort));
			HTREEITEM hUdpDstPort = m_cPacketsTree.InsertItem(szUdpDstPort, hUdp);
			TreeNodeData *pTndUdpDstPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpDstPort->dwStartPos = pTndUdpSrcPort->dwEndPos;
			pTndUdpDstPort->dwEndPos = pTndUdpDstPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpDstPort, (DWORD)pTndUdpDstPort);

			// [节点] UDP 长度
			static WCHAR szUdpLength[32];
			wsprintf(szUdpLength, _T("Length: %u"), ntohs(pUdpHdr->nLen));
			HTREEITEM hUdpLength = m_cPacketsTree.InsertItem(szUdpLength, hUdp);
			TreeNodeData *pTndUdpLength = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpLength->dwStartPos = pTndUdpDstPort->dwEndPos;
			pTndUdpLength->dwEndPos = pTndUdpLength->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpLength, (DWORD)pTndUdpLength);

			// [节点] UDP 校验和
			static WCHAR szUdpCrc[32];
			wsprintf(szUdpCrc, _T("Checksum: %u"), ntohs(pUdpHdr->nCrc));
			HTREEITEM hUdpCrc = m_cPacketsTree.InsertItem(szUdpCrc, hUdp);
			TreeNodeData *pTndUdpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpCrc->dwStartPos = pTndUdpLength->dwEndPos;
			pTndUdpCrc->dwEndPos = pTndUdpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpCrc, (DWORD)pTndUdpCrc);

			// [节点] UDP 数据
			if (pTndUdpCrc->dwEndPos < pNode->pHeader->caplen)
			{
				HTREEITEM hUdpData = m_cPacketsTree.InsertItem(_T("Data"), hUdp);
				TreeNodeData *pTndUdpData = (TreeNodeData *)malloc(sizeof(TreeNodeData));
				pTndUdpData->dwStartPos = pTndUdpCrc->dwEndPos;
				pTndUdpData->dwEndPos = pNode->pHeader->caplen;
				m_cPacketsTree.SetItemData(hUdpData, (DWORD)pTndUdpData);
			}
		}
	}

}
