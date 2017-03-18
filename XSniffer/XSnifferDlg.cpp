
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
//	ON_COMMAND(IDM_OPT_START, &CXSnifferDlg::OnOptStart)
ON_COMMAND(IDM_OPT_STARTCAP, &CXSnifferDlg::OnOptStartcap)
ON_COMMAND(IDM_OPT_STOPCAP, &CXSnifferDlg::OnOptStopcap)
ON_COMMAND(ID_FILE_CLOSE, &CXSnifferDlg::OnFileClose)
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
	m_dwArp = m_dwIcmp = m_dwIgmp = m_dwRef = m_dwTcp = 0;

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

void CXSnifferDlg::OnOptSetcapfilter()
{
	// TODO: 在此添加命令处理程序代码
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

