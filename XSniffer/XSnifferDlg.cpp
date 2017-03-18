
// XSnifferDlg.cpp : ʵ���ļ�
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


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CXSnifferDlg �Ի���



CXSnifferDlg::CXSnifferDlg(CWnd* pParent /*=NULL*/)
	: m_pAllDevs(NULL), m_tCapThread(NULL), m_tShowThread(NULL),/* �߳��ÿգ��豸���ÿ� */
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


// CXSnifferDlg ��Ϣ�������

BOOL CXSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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
	
	m_Menu.LoadMenu(IDR_MENU_MAIN);  //  IDR_MENU1Ϊ�����Ĳ˵���ID����Resource��ͼ��Menu�ļ����¿����ҵ�
	SetMenu(&m_Menu);

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	// ��ʼ���ؼ��Լ�WinPcap
	InitControls();
	InitWinPcap();

	// Ԥ��g_vcPackets�ռ�Ϊ 10MB
	g_vcPackets.reserve(10 * 1024 * 1024);

	// ��ʼ���ݰ�ͳ��
	m_dwArp = m_dwIcmp = m_dwIgmp = m_dwRef = m_dwTcp = 0;

	// ��ʼ��ʾ�߳�
	SAFE_DELETE(m_tShowThread);
	m_tShowThread = new CShowThread(m_dwTcp, m_dwUdp,
		m_dwArp, m_dwIgmp, m_dwIcmp, this);
	m_tShowThread->ResumeThread();

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CXSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CXSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// ��ʼ���ؼ�
BOOL CXSnifferDlg::InitControls()
{

	// �б���ͼ�ؼ� ��������
	DWORD dwStyle = m_cPacketsList.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;
	m_cPacketsList.SetExtendedStyle(dwStyle);

	// �б���ͼ�ؼ� �����ͷ
	CString csHeadStr;
	DWORD dwCol = 0;

	// ������ͷ�ַ���
	/* | ��� | ʱ�� | Դ������ַ | Ŀ��������ַ | Э������ | ���� | ���� | */
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_NO);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 60);	// ��һ��ʵ���ϲ������Ҷ���
	csHeadStr.LoadString(AfxGetInstanceHandle(), IDS_LH_TIME);
	m_cPacketsList.InsertColumn(dwCol++, csHeadStr, LVCFMT_LEFT, 120);	// ���������
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


	// ʮ�����ƿؼ�
	m_cHexView.m_pData = NULL;
	m_cHexView.m_length = 0;
	m_cHexView.m_bpr = 16;		// ÿ��16���ֽ�
	m_cHexView.m_lpp = 6;		// ÿҳ06������

	m_cHexView.SetReadOnly();

	// �������οؼ�����
	dwStyle = GetWindowLong(m_cPacketsTree.m_hWnd, GWL_STYLE);
	dwStyle |= TVS_LINESATROOT | TVS_HASBUTTONS | TVS_FULLROWSELECT;//| TVS_HASLINES;
	SetWindowLong(m_cPacketsTree.m_hWnd, GWL_STYLE, dwStyle);
	return 0;
}

// ��ʼ��WinPcap
BOOL CXSnifferDlg::InitWinPcap()
{
	char errbuf[PCAP_ERRBUF_SIZE + 1]; // ������Ϣ
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

	/* ��ýӿ��б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_pAllDevs, errbuf) == -1) {
		WCHAR *pszErrBuf = A2W(errbuf);
		MessageBox(pszErrBuf, _T("WinPcap��ʼ������"), MB_ICONERROR);
		return FALSE;
	}

	/* ���� */
	m_nCurAdapter = -1;

	/* ������ */
	ZeroMemory(&m_sCapFilter, sizeof(CaptureFilter)); // ������
	m_sCapFilter.dwProtocol = 31; // ȫ����λ

	/* ����״̬ */
	m_bCurCapture = FALSE;

	return 0;
}

// ����ʼ��WinPcap
void CXSnifferDlg::UnInitWinPcap()
{
	if (m_pAllDevs != NULL) {
		pcap_freealldevs(m_pAllDevs);
	}
}


// ��ȡm_cPacketsList���ʿ���
CListCtrl* CXSnifferDlg::GetPacketListWnd()
{
	return &m_cPacketsList;
}

// ��ȡm_cPacketNumBar���ʿ���
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


// ����ѡ�������Ի���
void CXSnifferDlg::OnOptSeldev()
{
	// TODO: �ڴ���������������
	if (m_bCurCapture)
	{
		MessageBox(_T("�Ѿ�����ץ��״̬�У����������������������ֹͣ����ץ����"),
			_T("��ʾ��Ϣ"), MB_ICONWARNING);
		return;
	}

	CAdaptersDlg dlg(this);
	dlg.DoModal();

	m_cPacketAdapter.SetWindowText(m_strCurAdapter);
}

void CXSnifferDlg::OnOptSetcapfilter()
{
	// TODO: �ڴ���������������
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
	// TODO: �ڴ���������������

	if (m_bCurCapture)
	{
		MessageBox(_T("�Ѿ�����ץ��״̬�У��������¿�ʼ����ֹͣ����ץ����"),
			_T("��ʾ��Ϣ"), MB_ICONWARNING);
		return;
	}

	int i = 0;
	pcap_if_t *d = m_pAllDevs;

	/* ��ת��ѡ�е������� */
	while (i < m_nCurAdapter)
	{
		++i;
		d = d->next;
	}

	// �������߳̿�ʼץ������
	SAFE_DELETE(m_tCapThread);
	m_tCapThread = new CCapThread(d, m_sCapFilter);

	if (-1 != m_tCapThread->ResumeThread())
	{
		m_bCurCapture = TRUE;
	}
}


void CXSnifferDlg::OnOptStopcap()
{
	// TODO: �ڴ���������������
	if (!m_bCurCapture)
	{
		MessageBox(_T("��ǰδ����ץ��״̬�����β������ԣ�"),
			_T("��ʾ��Ϣ"), MB_ICONWARNING);
		return;
	}

	SAFE_DELETE(m_tCapThread);
	m_bCurCapture = FALSE;
}


void CXSnifferDlg::OnFileClose()
{
	// TODO: �ڴ���������������
	SendMessage(WM_CLOSE, 0, 0);
}


void CXSnifferDlg::OnFileQuit()
{
	// TODO: �ڴ���������������
	SendMessage(WM_CLOSE, 0, 0);
}

void CXSnifferDlg::OnClose()
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ

	// ����ʼ��WinPcap
	UnInitWinPcap();
	// �ͷŷ���Ľڵ��ڴ�
	DeletePacket();
	CDialogEx::OnClose();
}

void CXSnifferDlg::OnAbout()
{
	// TODO: �ڴ���������������
	CAboutDlg dlg;
	dlg.DoModal();
}

