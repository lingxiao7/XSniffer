
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
extern WCHAR g_szIcmpType[42][40];
extern WCHAR g_szIgmpType[34][40];

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
	ON_COMMAND(IDM_OPT_STARTCAP, &CXSnifferDlg::OnOptStartcap)
	ON_COMMAND(IDM_OPT_STOPCAP, &CXSnifferDlg::OnOptStopcap)
	ON_COMMAND(ID_FILE_CLOSE, &CXSnifferDlg::OnFileClose)
	ON_NOTIFY(NM_CLICK, IDC_LIST_PACKETS, &CXSnifferDlg::OnClickListPackets)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE_PACKETS, &CXSnifferDlg::OnSelchangedTreePackets)
	ON_NOTIFY(TVN_DELETEITEM, IDC_TREE_PACKETS, &CXSnifferDlg::OnDeleteitemTreePackets)
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
	m_dwUdp = m_dwArp = m_dwIcmp = m_dwIgmp = m_dwRef = m_dwTcp = 0;

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

// �����������Ի���
void CXSnifferDlg::OnOptSetcapfilter()
{
	// TODO: �ڴ���������������
	if (m_bCurCapture)
	{
		MessageBox(_T("�Ѿ�����ץ��״̬�У����������������������ֹͣ����ץ����"),
			_T("��ʾ��Ϣ"), MB_ICONWARNING);
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



void CXSnifferDlg::OnClickListPackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	DWORD dwIndex = pNMItemActivate->iItem;
	DWORD dwSize = g_vcPackets.size();

	if (dwIndex >= 0 && dwIndex < dwSize) {
		PacketNode *pNode = g_vcPackets[dwIndex];

		// ���οؼ�������ʾ
		UpdateTreeViewData(dwIndex);

		// BugFix: ʮ�����ƿؼ��Ĵ�ֱ�������е�����
		// �����������β�����
		m_cHexView.SetData(pNode->pData, pNode->pHeader->caplen);
		m_cHexView.SetData(pNode->pData, pNode->pHeader->caplen);
		m_cHexView.Invalidate();
	}

	*pResult = 0;
}


void CXSnifferDlg::OnSelchangedTreePackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	HTREEITEM hNode = m_cPacketsTree.GetSelectedItem();
	if (hNode == NULL) return;

	TreeNodeData *pTnd = (TreeNodeData *)(m_cPacketsTree.GetItemData(hNode));
	m_cHexView.SetSel(pTnd->dwStartPos, pTnd->dwEndPos);

	*pResult = 0;
}


void CXSnifferDlg::OnDeleteitemTreePackets(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	if (pNMTreeView->itemOld.lParam != NULL)
	{
		free((TreeNodeData *)(pNMTreeView->itemOld.lParam));
	}

	*pResult = 0;
}


// ����TreeView����
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

	// [�ڵ�] Ethernetͷ������
	HTREEITEM hEthernet = m_cPacketsTree.InsertItem(_T("Ethernet"));
	TreeNodeData *pTndEthernet = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthernet->dwStartPos = 0;
	pTndEthernet->dwEndPos = pTndEthernet->dwStartPos + sizeof(EthernetHeader);
	m_cPacketsTree.SetItemData(hEthernet, (DWORD)pTndEthernet);

	// [�ڵ�] DstMacͷ������
	HTREEITEM hEthDstMac = m_cPacketsTree.InsertItem(szDstMac, hEthernet);
	TreeNodeData *pTndEthDstMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthDstMac->dwStartPos = 0;
	pTndEthDstMac->dwEndPos = pTndEthDstMac->dwStartPos + sizeof(MacAddr);
	m_cPacketsTree.SetItemData(hEthDstMac, (DWORD)pTndEthDstMac);

	// [�ڵ�] SrcMacͷ������
	HTREEITEM hEthSrcMac = m_cPacketsTree.InsertItem(szSrcMac, hEthernet);
	TreeNodeData *pTndEthSrcMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthSrcMac->dwStartPos = pTndEthDstMac->dwEndPos;
	pTndEthSrcMac->dwEndPos = pTndEthSrcMac->dwStartPos + sizeof(MacAddr);
	m_cPacketsTree.SetItemData(hEthSrcMac, (DWORD)pTndEthSrcMac);

	// Э�����͸�������
	TreeNodeData *pTndEthProtoType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
	pTndEthProtoType->dwStartPos = pTndEthSrcMac->dwEndPos;
	pTndEthProtoType->dwEndPos = pTndEthProtoType->dwStartPos + 2;

	// ==========================================================================
	// ARP���ݰ�����
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

		// ARPͷ����ʽ����
		ArpHeader *pArpHdr = (ArpHeader *)(pNode->pData + sizeof(EthernetHeader));

		// ���ͷ�MAC��ַ��IP��ַ
		wsprintf(szSrcMac, _T("Sender MAC address: %02X-%02X-%02X-%02X-%02X-%02X"),
			pArpHdr->sSrcMac.byte1, pArpHdr->sSrcMac.byte2, pArpHdr->sSrcMac.byte3,
			pArpHdr->sSrcMac.byte4, pArpHdr->sSrcMac.byte5, pArpHdr->sSrcMac.byte6);
		wsprintf(szSrcIp, _T("Sender IP address: %d.%d.%d.%d"), pArpHdr->sSrcIp.byte1,
			pArpHdr->sSrcIp.byte2, pArpHdr->sSrcIp.byte3, pArpHdr->sSrcIp.byte4);

		// ���շ�MAC��ַ��IP��ַ
		wsprintf(szDstMac, _T("Target MAC address: %02X-%02X-%02X-%02X-%02X-%02X"),
			pArpHdr->sDstMac.byte1, pArpHdr->sDstMac.byte2, pArpHdr->sDstMac.byte3,
			pArpHdr->sDstMac.byte4, pArpHdr->sDstMac.byte5, pArpHdr->sDstMac.byte6);
		wsprintf(szSrcIp, _T("Sender IP address: %d.%d.%d.%d"), pArpHdr->sDstIp.byte1,
			pArpHdr->sDstIp.byte2, pArpHdr->sDstIp.byte3, pArpHdr->sDstIp.byte4);

		// ARP������
		unsigned short uOpcode = ntohs(pArpHdr->nOpCode);
		if (uOpcode > 2) uOpcode = 0; // δ����

									  // [�ڵ�] EthernetЭ���ֶ�: Э������
		wcscpy(szProtocolType, _T("Type: ARP (0x0806)"));
		HTREEITEM hEthProtoType = m_cPacketsTree.InsertItem(szProtocolType, hEthernet);
		m_cPacketsTree.SetItemData(hEthProtoType, (DWORD)pTndEthProtoType);

		// [�ڵ�] ARPͷ������
		HTREEITEM hArp = m_cPacketsTree.InsertItem(_T("Address Resolution Protocol"));
		TreeNodeData *pTndArp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndArp->dwStartPos = pTndEthProtoType->dwEndPos;
		pTndArp->dwEndPos = pTndArp->dwStartPos + sizeof(ArpHeader);
		m_cPacketsTree.SetItemData(hArp, (DWORD)pTndArp);

		// [�ڵ�] Ӳ������
		wsprintf(szHardwareType, _T("Hardware type: 0x%04X"),
			ntohs(pArpHdr->nHardType));
		HTREEITEM hHardwareType = m_cPacketsTree.InsertItem(szHardwareType, hArp);
		TreeNodeData *pTndHardwareType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndHardwareType->dwStartPos = pTndArp->dwStartPos;
		pTndHardwareType->dwEndPos = pTndHardwareType->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hHardwareType, (DWORD)pTndHardwareType);

		// [�ڵ�] Э������
		wsprintf(szProtocolType, _T("Protocol type: 0x%04X"),
			ntohs(pArpHdr->nProtoType));
		HTREEITEM hProtocolType = m_cPacketsTree.InsertItem(szProtocolType, hArp);
		TreeNodeData *pTndProtocolType = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndProtocolType->dwStartPos = pTndHardwareType->dwEndPos;
		pTndProtocolType->dwEndPos = pTndProtocolType->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hProtocolType, (DWORD)pTndProtocolType);

		// [�ڵ�] Ӳ����С
		wsprintf(szHardwareSize, _T("Hardware size: 0x%02X"),
			pArpHdr->nMacLen);
		HTREEITEM hHardwareSize = m_cPacketsTree.InsertItem(szHardwareSize, hArp);
		TreeNodeData *pTndHardwareSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndHardwareSize->dwStartPos = pTndProtocolType->dwEndPos;
		pTndHardwareSize->dwEndPos = pTndHardwareSize->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hHardwareSize, (DWORD)pTndHardwareSize);

		// [�ڵ�] Э���С
		wsprintf(szProtocolSize, _T("Protocol size: 0x%02X"),
			pArpHdr->nProtoLen);
		HTREEITEM hProtocolSize = m_cPacketsTree.InsertItem(szProtocolSize, hArp);
		TreeNodeData *pTndProtocolSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndProtocolSize->dwStartPos = pTndHardwareSize->dwEndPos;
		pTndProtocolSize->dwEndPos = pTndProtocolSize->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hProtocolSize, (DWORD)pTndProtocolSize);

		// [�ڵ�] ������
		wsprintf(szOpcode, _T("Opcode: 0x%04X (%s)"),
			ntohs(pArpHdr->nOpCode), szOpString[uOpcode]);
		HTREEITEM hOpcode = m_cPacketsTree.InsertItem(szOpcode, hArp);
		TreeNodeData *pTndOpcode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndOpcode->dwStartPos = pTndProtocolSize->dwEndPos;
		pTndOpcode->dwEndPos = pTndOpcode->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hOpcode, (DWORD)pTndOpcode);

		// [�ڵ�] ���ͷ�MAC��ַ
		HTREEITEM hSrcMac = m_cPacketsTree.InsertItem(szSrcMac, hArp);
		TreeNodeData *pTndSrcMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcMac->dwStartPos = pTndOpcode->dwEndPos;
		pTndSrcMac->dwEndPos = pTndSrcMac->dwStartPos + sizeof(MacAddr);
		m_cPacketsTree.SetItemData(hSrcMac, (DWORD)pTndSrcMac);

		// [�ڵ�] ���ͷ�IP��ַ
		HTREEITEM hSrcIp = m_cPacketsTree.InsertItem(szSrcIp, hArp);
		TreeNodeData *pTndSrcIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcIp->dwStartPos = pTndSrcMac->dwEndPos;
		pTndSrcIp->dwEndPos = pTndSrcIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hSrcIp, (DWORD)pTndSrcIp);

		// [�ڵ�] ���շ�MAC��ַ
		HTREEITEM hDstMac = m_cPacketsTree.InsertItem(szDstMac, hArp);
		TreeNodeData *pTndDstMac = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstMac->dwStartPos = pTndSrcIp->dwEndPos;
		pTndDstMac->dwEndPos = pTndDstMac->dwStartPos + sizeof(MacAddr);
		m_cPacketsTree.SetItemData(hDstMac, (DWORD)pTndDstMac);

		// [�ڵ�] ���շ�IP��ַ
		HTREEITEM hDstIp = m_cPacketsTree.InsertItem(szDstIp, hArp);
		TreeNodeData *pTndDstIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstIp->dwStartPos = pTndDstMac->dwEndPos;
		pTndDstIp->dwEndPos = pTndDstIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hDstIp, (DWORD)pTndDstIp);
	}
	// ==========================================================================
	// IP���ݰ�����
	// ==========================================================================
	else if (ntohs(pEthHeader->nEthType) == 0x0800)
	{
		IpHeader *pIpHdr = (IpHeader *)(pNode->pData + sizeof(EthernetHeader));
		DWORD dwIpHdrLen = (pIpHdr->nVerHl & 0xf) * 4;	// һ��Ҫ����4

													// [�ڵ�] EthernetЭ���ֶ�: Э������
		wcscpy(szProtocolType, _T("Type: IP (0x0800)"));
		HTREEITEM hEthProtoType = m_cPacketsTree.InsertItem(szProtocolType, hEthernet);
		m_cPacketsTree.SetItemData(hEthProtoType, (DWORD)pTndEthProtoType);

		// [�ڵ�] IPͷ������
		HTREEITEM hIp = m_cPacketsTree.InsertItem(_T("Internet Protocol"));
		TreeNodeData *pTndIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIp->dwStartPos = pTndEthProtoType->dwEndPos;
		pTndIp->dwEndPos = pTndIp->dwStartPos + sizeof(IpHeader);
		m_cPacketsTree.SetItemData(hIp, (DWORD)pTndIp);

		// [�ڵ�] IP�汾
		static WCHAR szIpVer[16];
		wsprintf(szIpVer, _T("Version: %u"), (pIpHdr->nVerHl & 0xf0));
		HTREEITEM hIpVer = m_cPacketsTree.InsertItem(szIpVer, hIp);
		TreeNodeData *pTndIpVer = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpVer->dwStartPos = pTndIp->dwStartPos;
		pTndIpVer->dwEndPos = pTndIpVer->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpVer, (DWORD)pTndIpVer);

		// [�ڵ�] IP ͷ������
		static WCHAR szIpHdrLen[32];
		wsprintf(szIpHdrLen, _T("Header length: %u bytes"), dwIpHdrLen);
		HTREEITEM hIpHdrLen = m_cPacketsTree.InsertItem(szIpHdrLen, hIp);
		TreeNodeData *pTndIpHdrLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpHdrLen->dwStartPos = pTndIp->dwStartPos;
		pTndIpHdrLen->dwEndPos = pTndIpHdrLen->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpHdrLen, (DWORD)pTndIpHdrLen);

		// [�ڵ�] IP ��������
		static WCHAR szIpTos[64];
		wsprintf(szIpTos, _T("Differentiated Services Field: 0x%02X"), pIpHdr->nTos);
		HTREEITEM hIpTos = m_cPacketsTree.InsertItem(szIpTos, hIp);
		TreeNodeData *pTndIpTos = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIpTos->dwStartPos = pTndIpHdrLen->dwEndPos;
		pTndIpTos->dwEndPos = pTndIpTos->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpTos, (DWORD)pTndIpTos);

		// [�ڵ�] IP �ܳ���
		static WCHAR szIpTotalLen[64];
		wsprintf(szIpTotalLen, _T("Total length: 0x%04X"), ntohs(pIpHdr->nTotalLen));
		HTREEITEM hIpTotalLen = m_cPacketsTree.InsertItem(szIpTotalLen, hIp);
		TreeNodeData *pTndTotalLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndTotalLen->dwStartPos = pTndIpTos->dwEndPos;
		pTndTotalLen->dwEndPos = pTndTotalLen->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpTotalLen, (DWORD)pTndTotalLen);

		// [�ڵ�] IP ��ʶ
		static WCHAR szIpIdent[64];
		wsprintf(szIpIdent, _T("Identification: 0x%04X"), ntohs(pIpHdr->nIdent));
		HTREEITEM hIpIdent = m_cPacketsTree.InsertItem(szIpIdent, hIp);
		TreeNodeData *pTndIdent = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndIdent->dwStartPos = pTndTotalLen->dwEndPos;
		pTndIdent->dwEndPos = pTndIdent->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpIdent, (DWORD)pTndIdent);

		// [�ڵ�] IP ��Ƭƫ��
		static WCHAR szIpFragOff[64];
		wsprintf(szIpFragOff, _T("Fragment offset: %u"), ntohs(pIpHdr->nFragOff));
		HTREEITEM hIpFragOff = m_cPacketsTree.InsertItem(szIpFragOff, hIp);
		TreeNodeData *pTndFragOff = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndFragOff->dwStartPos = pTndIdent->dwEndPos;
		pTndFragOff->dwEndPos = pTndFragOff->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpFragOff, (DWORD)pTndFragOff);

		// [�ڵ�] IP TTL
		static WCHAR szIpTtl[64];
		wsprintf(szIpTtl, _T("Time to live: %u"), pIpHdr->nTtl);
		HTREEITEM hIpTtl = m_cPacketsTree.InsertItem(szIpTtl, hIp);
		TreeNodeData *pTndTtl = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndTtl->dwStartPos = pTndFragOff->dwEndPos;
		pTndTtl->dwEndPos = pTndTtl->dwStartPos + sizeof(unsigned char);
		m_cPacketsTree.SetItemData(hIpTtl, (DWORD)pTndTtl);

		// [�ڵ�] IP Э������
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

		// [�ڵ�] IP ͷ��У��
		static WCHAR szIpCrc[64];
		wsprintf(szIpCrc, _T("Header checksum: 0x%04X"), ntohs(pIpHdr->nCrc));
		HTREEITEM hIpCrc = m_cPacketsTree.InsertItem(szIpCrc, hIp);
		TreeNodeData *pTndCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndCrc->dwStartPos = pTndProto->dwEndPos;
		pTndCrc->dwEndPos = pTndCrc->dwStartPos + sizeof(unsigned short);
		m_cPacketsTree.SetItemData(hIpCrc, (DWORD)pTndCrc);

		// [�ڵ�] IP ���ͷ�IP��ַ
		static WCHAR szIpSrcIp[64];
		wsprintf(szIpSrcIp, _T("Source: %d.%d.%d.%d"), pIpHdr->sSrcIp.byte1,
			pIpHdr->sSrcIp.byte2, pIpHdr->sSrcIp.byte3, pIpHdr->sSrcIp.byte4);
		HTREEITEM hIpSrcIp = m_cPacketsTree.InsertItem(szIpSrcIp, hIp);
		TreeNodeData *pTndSrcIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndSrcIp->dwStartPos = pTndCrc->dwEndPos;
		pTndSrcIp->dwEndPos = pTndSrcIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hIpSrcIp, (DWORD)pTndSrcIp);

		// [�ڵ�] IP ���շ�IP��ַ
		static WCHAR szIpDstIp[64];
		wsprintf(szIpDstIp, _T("Source: %d.%d.%d.%d"), pIpHdr->sDstIp.byte1,
			pIpHdr->sDstIp.byte2, pIpHdr->sDstIp.byte3, pIpHdr->sDstIp.byte4);
		HTREEITEM hIpDstIp = m_cPacketsTree.InsertItem(szIpDstIp, hIp);
		TreeNodeData *pTndDstIp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
		pTndDstIp->dwStartPos = pTndSrcIp->dwEndPos;
		pTndDstIp->dwEndPos = pTndDstIp->dwStartPos + sizeof(IpAddr);
		m_cPacketsTree.SetItemData(hIpDstIp, (DWORD)pTndDstIp);

		// ======================================================================
		// ICMP���ݰ�����
		// ======================================================================
		if (pIpHdr->nProtocol == 1)
		{
			// [�ڵ�] ICMPͷ������
			HTREEITEM hIcmp = m_cPacketsTree.InsertItem(_T("Internet Control Message Protocol"));
			TreeNodeData *pTndIcmp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndIcmp->dwEndPos = pNode->pHeader->caplen;
			m_cPacketsTree.SetItemData(hIcmp, (DWORD)pTndIcmp);

			// [�ڵ�] ICMP ����
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

			// [�ڵ�] ICMP Code
			static WCHAR szIcmpCode[16];
			wsprintf(szIcmpCode, _T("Code: %d"), pIcmpHdr->nCode);
			HTREEITEM hIcmpCode = m_cPacketsTree.InsertItem(szIcmpCode, hIcmp);
			TreeNodeData *pTndIcmpCode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCode->dwStartPos = pTndIcmpType->dwEndPos;
			pTndIcmpCode->dwEndPos = pTndIcmpCode->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIcmpCode, (DWORD)pTndIcmpCode);

			// [�ڵ�] ICMP У��
			static WCHAR szIcmpCrc[32];
			wsprintf(szIcmpCrc, _T("Checksum: 0x%04X"), ntohs(pIcmpHdr->nCheckSum));
			HTREEITEM hIcmpCrc = m_cPacketsTree.InsertItem(szIcmpCrc, hIcmp);
			TreeNodeData *pTndIcmpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCrc->dwStartPos = pTndIcmpCode->dwEndPos;
			pTndIcmpCrc->dwEndPos = pTndIcmpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hIcmpCrc, (DWORD)pTndIcmpCrc);
		}
		// ======================================================================
		// IGMP���ݰ�����
		// ======================================================================
		else if (pIpHdr->nProtocol == 2)
		{
			// [�ڵ�] IGMPͷ������
			HTREEITEM hIgmp = m_cPacketsTree.InsertItem(_T("Internet Group Management Protocol"));
			TreeNodeData *pTndIgmp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIgmp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndIgmp->dwEndPos = pNode->pHeader->caplen;
			m_cPacketsTree.SetItemData(hIgmp, (DWORD)pTndIgmp);

			// [�ڵ�] IGMP ����
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

			// [�ڵ�] IGMP Code
			static WCHAR szIgmpCode[16];
			wsprintf(szIgmpCode, _T("Code: %d"), pIgmpHdr->nCode);
			HTREEITEM hIgmpCode = m_cPacketsTree.InsertItem(szIgmpCode, hIgmp);
			TreeNodeData *pTndIgmpCode = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIgmpCode->dwStartPos = pTndIgmpType->dwEndPos;
			pTndIgmpCode->dwEndPos = pTndIgmpCode->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hIgmpCode, (DWORD)pTndIgmpCode);

			// [�ڵ�] IGMP У��
			static WCHAR szIgmpCrc[32];
			wsprintf(szIgmpCrc, _T("Checksum: 0x%04X"), ntohs(pIgmpHdr->nCheckSum));
			HTREEITEM hIgmpCrc = m_cPacketsTree.InsertItem(szIgmpCrc, hIgmp);
			TreeNodeData *pTndIcmpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndIcmpCrc->dwStartPos = pTndIgmpCode->dwEndPos;
			pTndIcmpCrc->dwEndPos = pTndIcmpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hIgmpCrc, (DWORD)hIgmpCrc);
		}
		// ======================================================================
		// TCP���ݰ�����
		// ======================================================================
		else if (pIpHdr->nProtocol == 6)
		{
			TcpHeader *pTcpHdr = (TcpHeader *)((BYTE*)pIpHdr + dwIpHdrLen);

			// [�ڵ�] TCPͷ������
			HTREEITEM hTcp = m_cPacketsTree.InsertItem(_T("Transmission Control Protocol"));
			TreeNodeData *pTndTcp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndTcp->dwEndPos = pTndTcp->dwStartPos + sizeof(TcpHeader);
			m_cPacketsTree.SetItemData(hTcp, (DWORD)pTndTcp);

			// [�ڵ�] TCP ���ͷ��˿�
			static WCHAR szTcpSrcPort[32];
			wsprintf(szTcpSrcPort, _T("Source port: %d"), ntohs(pTcpHdr->nSrcPort));
			HTREEITEM hTcpSrcPort = m_cPacketsTree.InsertItem(szTcpSrcPort, hTcp);
			TreeNodeData *pTndTcpSrcPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpSrcPort->dwStartPos = pTndTcp->dwStartPos;
			pTndTcpSrcPort->dwEndPos = pTndTcpSrcPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpSrcPort, (DWORD)pTndTcpSrcPort);

			// [�ڵ�] TCP ���շ��˿�
			static WCHAR szTcpDstPort[32];
			wsprintf(szTcpDstPort, _T("Destination port: %d"), ntohs(pTcpHdr->nDstPort));
			HTREEITEM hTcpDstPort = m_cPacketsTree.InsertItem(szTcpDstPort, hTcp);
			TreeNodeData *pTndTcpDstPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpDstPort->dwStartPos = pTndTcpSrcPort->dwEndPos;
			pTndTcpDstPort->dwEndPos = pTndTcpDstPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpDstPort, (DWORD)pTndTcpDstPort);

			// [�ڵ�] TCP SeqNum
			static WCHAR szTcpSeqNum[32];
			wsprintf(szTcpSeqNum, _T("SeqNum: %lu"), ntohl(pTcpHdr->nSeqNum));
			HTREEITEM hTcpSeqNum = m_cPacketsTree.InsertItem(szTcpSeqNum, hTcp);
			TreeNodeData *pTndTcpSeqNum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpSeqNum->dwStartPos = pTndTcpDstPort->dwEndPos;
			pTndTcpSeqNum->dwEndPos = pTndTcpSeqNum->dwStartPos + sizeof(unsigned long);
			m_cPacketsTree.SetItemData(hTcpSeqNum, (DWORD)pTndTcpSeqNum);

			// [�ڵ�] TCP AckNum
			static WCHAR szTcpAckNum[32];
			wsprintf(szTcpAckNum, _T("AckNum: %lu"), ntohl(pTcpHdr->nAckNum));
			HTREEITEM hTcpAckNum = m_cPacketsTree.InsertItem(szTcpAckNum, hTcp);
			TreeNodeData *pTndTcpAckNum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpAckNum->dwStartPos = pTndTcpSeqNum->dwEndPos;
			pTndTcpAckNum->dwEndPos = pTndTcpAckNum->dwStartPos + sizeof(unsigned long);
			m_cPacketsTree.SetItemData(hTcpAckNum, (DWORD)pTndTcpAckNum);

			// [�ڵ�] TCP HeaderLen
			static WCHAR szTcpHeaderLen[32];
			wsprintf(szTcpHeaderLen, _T("Header length: %d"), pTcpHdr->nHeaderLen);
			HTREEITEM hTcpHeaderLen = m_cPacketsTree.InsertItem(szTcpHeaderLen, hTcp);
			TreeNodeData *pTndTcpHeaderLen = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpHeaderLen->dwStartPos = pTndTcpAckNum->dwEndPos;
			pTndTcpHeaderLen->dwEndPos = pTndTcpHeaderLen->dwStartPos + sizeof(unsigned char);
			m_cPacketsTree.SetItemData(hTcpHeaderLen, (DWORD)pTndTcpHeaderLen);

			// [�ڵ�] TCP Flags
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

			// [�ڵ�] TCP WinSize
			static WCHAR szTcpWinSize[32];
			wsprintf(szTcpWinSize, _T("Window size value: %u"), ntohl(pTcpHdr->nWinSize));
			HTREEITEM hTcpWinSize = m_cPacketsTree.InsertItem(szTcpWinSize, hTcp);
			TreeNodeData *pTndTcpWinSize = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpWinSize->dwStartPos = pTndTcpFlags->dwEndPos;
			pTndTcpWinSize->dwEndPos = pTndTcpWinSize->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpWinSize, (DWORD)pTndTcpWinSize);

			// [�ڵ�] TCP CheckSum
			static WCHAR szTcpCheckSum[32];
			wsprintf(szTcpCheckSum, _T("Checksum: 0x%02X"), ntohl(pTcpHdr->nCheckSum));
			HTREEITEM hTcpCheckSum = m_cPacketsTree.InsertItem(szTcpCheckSum, hTcp);
			TreeNodeData *pTndTcpCheckSum = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpCheckSum->dwStartPos = pTndTcpWinSize->dwEndPos;
			pTndTcpCheckSum->dwEndPos = pTndTcpCheckSum->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpCheckSum, (DWORD)pTndTcpCheckSum);

			// [�ڵ�] TCP UrgPtr
			static WCHAR szTcpUrgPtr[32];
			wsprintf(szTcpUrgPtr, _T("UrgPtr: 0x%02X"), ntohl(pTcpHdr->nUrgPtr));
			HTREEITEM hTcpUrgPtr = m_cPacketsTree.InsertItem(szTcpUrgPtr, hTcp);
			TreeNodeData *pTndTcpUrgPtr = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndTcpUrgPtr->dwStartPos = pTndTcpCheckSum->dwEndPos;
			pTndTcpUrgPtr->dwEndPos = pTndTcpUrgPtr->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hTcpUrgPtr, (DWORD)pTndTcpUrgPtr);

			// [�ڵ�] TCP ����
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
		// UDP���ݰ�����
		// ======================================================================
		else if (pIpHdr->nProtocol == 17)
		{
			UdpHeader *pUdpHdr = (UdpHeader *)((BYTE*)pIpHdr + dwIpHdrLen);
			// [�ڵ�] UDPͷ������
			HTREEITEM hUdp = m_cPacketsTree.InsertItem(_T("User Datagram Protocol"));
			TreeNodeData *pTndUdp = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdp->dwStartPos = pTndIp->dwStartPos + dwIpHdrLen;
			pTndUdp->dwEndPos = pTndUdp->dwStartPos + sizeof(UdpHeader);
			m_cPacketsTree.SetItemData(hUdp, (DWORD)pTndUdp);

			// [�ڵ�] UDP ���ͷ��˿�
			static WCHAR szUdpSrcPort[32];
			wsprintf(szUdpSrcPort, _T("Source port: %d"), ntohs(pUdpHdr->nSrcPort));
			HTREEITEM hUdpSrcPort = m_cPacketsTree.InsertItem(szUdpSrcPort, hUdp);
			TreeNodeData *pTndUdpSrcPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpSrcPort->dwStartPos = pTndUdp->dwStartPos;
			pTndUdpSrcPort->dwEndPos = pTndUdpSrcPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpSrcPort, (DWORD)pTndUdpSrcPort);

			// [�ڵ�] UDP ���շ��˿�
			static WCHAR szUdpDstPort[32];
			wsprintf(szUdpDstPort, _T("Destination port: %d"), ntohs(pUdpHdr->nDstPort));
			HTREEITEM hUdpDstPort = m_cPacketsTree.InsertItem(szUdpDstPort, hUdp);
			TreeNodeData *pTndUdpDstPort = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpDstPort->dwStartPos = pTndUdpSrcPort->dwEndPos;
			pTndUdpDstPort->dwEndPos = pTndUdpDstPort->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpDstPort, (DWORD)pTndUdpDstPort);

			// [�ڵ�] UDP ����
			static WCHAR szUdpLength[32];
			wsprintf(szUdpLength, _T("Length: %u"), ntohs(pUdpHdr->nLen));
			HTREEITEM hUdpLength = m_cPacketsTree.InsertItem(szUdpLength, hUdp);
			TreeNodeData *pTndUdpLength = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpLength->dwStartPos = pTndUdpDstPort->dwEndPos;
			pTndUdpLength->dwEndPos = pTndUdpLength->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpLength, (DWORD)pTndUdpLength);

			// [�ڵ�] UDP У���
			static WCHAR szUdpCrc[32];
			wsprintf(szUdpCrc, _T("Checksum: %u"), ntohs(pUdpHdr->nCrc));
			HTREEITEM hUdpCrc = m_cPacketsTree.InsertItem(szUdpCrc, hUdp);
			TreeNodeData *pTndUdpCrc = (TreeNodeData *)malloc(sizeof(TreeNodeData));
			pTndUdpCrc->dwStartPos = pTndUdpLength->dwEndPos;
			pTndUdpCrc->dwEndPos = pTndUdpCrc->dwStartPos + sizeof(unsigned short);
			m_cPacketsTree.SetItemData(hUdpCrc, (DWORD)pTndUdpCrc);

			// [�ڵ�] UDP ����
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
