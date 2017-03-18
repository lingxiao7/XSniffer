// CapfilterDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "XSniffer.h"
#include "CapfilterDlg.h"
#include "afxdialogex.h"


// CCapfilterDlg 对话框

IMPLEMENT_DYNAMIC(CCapfilterDlg, CDialogEx)

CCapfilterDlg::CCapfilterDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_CAPFILTER, pParent)
{

}

CCapfilterDlg::CCapfilterDlg(CXSnifferDlg * pOwnerDlg,
	CaptureFilter sCaptureFilter, CWnd * pParent/*=NULL*/)
	: CDialogEx(IDD_DIALOG_CAPFILTER, pParent),
	m_pOwnerDlg(pOwnerDlg), m_sCaptureFilter(sCaptureFilter)
{
}

CCapfilterDlg::~CCapfilterDlg()
{
}

void CCapfilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK_ARP, m_cArp);
	DDX_Control(pDX, IDC_CHECK_ICMP, m_cIcmp);
	DDX_Control(pDX, IDC_CHECK_IGMP, m_cIgmp);
	DDX_Control(pDX, IDC_CHECK_SENDERIP, m_cChkSenderIp);
	DDX_Control(pDX, IDC_CHECK_SENDERUDP, m_cChkSenderUdp);
	DDX_Control(pDX, IDC_CHECK_TARGETUDP, m_cChkTargetUdp);
	DDX_Control(pDX, IDC_CHECK_TCP, m_cTcp);
	DDX_Control(pDX, IDC_CHECK_TEAGETIP, m_cChkTargetIp);
	DDX_Control(pDX, IDC_CHECK_UDP, m_cUdp);
	DDX_Control(pDX, IDC_EDIT_SENDERUPD, m_cEdtSenderUdp);
	DDX_Control(pDX, IDC_EDIT_TARGETUDP, m_cEdtTargetUdp);
	DDX_Control(pDX, IDC_IPADDRESS_SENDER, m_cIpSender);
	DDX_Control(pDX, IDC_IPADDRESS_TARGET, m_cIpTarget);
}


BEGIN_MESSAGE_MAP(CCapfilterDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CCapfilterDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_CHECK_TCP, &CCapfilterDlg::OnClickedCheckTcp)
	ON_BN_CLICKED(IDC_CHECK_UDP, &CCapfilterDlg::OnClickedCheckUdp)
END_MESSAGE_MAP()


// CCapfilterDlg 消息处理程序



BOOL CCapfilterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	if (m_sCaptureFilter.dwProtocol & CAP_FILTER_TCP) m_cTcp.SetCheck(BST_CHECKED);
	if (m_sCaptureFilter.dwProtocol & CAP_FILTER_UDP) m_cUdp.SetCheck(BST_CHECKED);
	if (m_sCaptureFilter.dwProtocol & CAP_FILTER_ARP) m_cArp.SetCheck(BST_CHECKED);
	if (m_sCaptureFilter.dwProtocol & CAP_FILTER_ICMP) m_cIcmp.SetCheck(BST_CHECKED);
	if (m_sCaptureFilter.dwProtocol & CAP_FILTER_IGMP) m_cIgmp.SetCheck(BST_CHECKED);


	if (!(m_sCaptureFilter.dwProtocol & CAP_FILTER_TCP) &&
		!(m_sCaptureFilter.dwProtocol & CAP_FILTER_UDP))
	{
		m_cChkSenderUdp.EnableWindow(FALSE);
		m_cChkTargetUdp.EnableWindow(FALSE);
		m_cEdtSenderUdp.SetReadOnly(TRUE);
		m_cEdtTargetUdp.SetReadOnly(TRUE);
	}
	else
	{
		if (m_sCaptureFilter.bSrcPort)
		{
			m_cChkSenderUdp.SetCheck(BST_CHECKED);
			SetDlgItemInt(m_cEdtSenderUdp.GetDlgCtrlID(),
				m_sCaptureFilter.dwSrcPort, 0);
		}
		if (m_sCaptureFilter.bDstPort)
		{
			m_cChkTargetUdp.SetCheck(BST_CHECKED);
			SetDlgItemInt(m_cEdtTargetUdp.GetDlgCtrlID(),
				m_sCaptureFilter.dwDstPort, 0);
		}
	}

	if (m_sCaptureFilter.bSrcIp)
	{
		m_cChkSenderIp.SetCheck(BST_CHECKED);
		m_cIpSender.SetAddress(m_sCaptureFilter.dwSrcIp);
	}

	if (m_sCaptureFilter.bDstIp)
	{
		m_cChkTargetIp.SetCheck(BST_CHECKED);
		m_cIpTarget.SetAddress(m_sCaptureFilter.dwDstIp);
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


void CCapfilterDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwCapFilter = 0;
	if (m_cTcp.GetCheck()) dwCapFilter |= CAP_FILTER_TCP;
	if (m_cUdp.GetCheck()) dwCapFilter |= CAP_FILTER_UDP;
	if (m_cArp.GetCheck()) dwCapFilter |= CAP_FILTER_ARP;
	if (m_cIcmp.GetCheck()) dwCapFilter |= CAP_FILTER_ICMP;
	if (m_cIgmp.GetCheck()) dwCapFilter |= CAP_FILTER_IGMP;

	if (!(dwCapFilter))
	{
		MessageBox(_T("至少需要选择一种数据包格式！"),
			_T("提示信息"), MB_ICONWARNING);
		return;
	}

	char buff[16];
	WCHAR wBuff[16];
	DWORD dwNum;
	if (m_cTcp.GetCheck() || m_cUdp.GetCheck())
	{
		if (m_cChkSenderUdp.GetCheck())
		{
			m_cEdtSenderUdp.GetWindowText(wBuff, 16);
			if (wcslen(wBuff) == 0)
			{
				MessageBox(_T("端口数值范围必须在区间[0, 65535]上！"),
					_T("提示信息"), MB_ICONWARNING);
				return;
			}
			else
			{
				WideCharToMultiByte(CP_ACP, 0, wBuff, -1, buff, 16, NULL, NULL);
				dwNum = atoi(buff);
				if (dwNum >= 0 && dwNum <= 65535)
				{
					m_sCaptureFilter.bSrcPort = 1;
					m_sCaptureFilter.dwSrcPort = dwNum;
				}
				else
				{
					MessageBox(_T("端口数值范围必须在区间[0, 65535]上！"),
						_T("提示信息"), MB_ICONWARNING);
					return;
				}
			}
		}
		else
		{
			m_sCaptureFilter.bSrcPort = 0;
		}

		if (m_cChkTargetUdp.GetCheck())
		{
			m_cEdtTargetUdp.GetWindowText(wBuff, 16);
			if (wcslen(wBuff) == 0)
			{
				MessageBox(_T("端口数值范围必须在区间[0, 65535]上！"),
					_T("提示信息"), MB_ICONWARNING);
				return;
			}
			else
			{
				WideCharToMultiByte(CP_ACP, 0, wBuff, -1, buff, 16, NULL, NULL);
				dwNum = atoi(buff);
				if (dwNum >= 0 && dwNum <= 65535)
				{
					m_sCaptureFilter.bDstPort = 1;
					m_sCaptureFilter.dwDstPort = dwNum;
				}
				else
				{
					MessageBox(_T("端口数值范围必须在区间[0, 65535]上！"),
						_T("提示信息"), MB_ICONWARNING);
					return;
				}
			}
		}
		else
		{
			m_sCaptureFilter.bDstPort = 0;
		}
	}

	// 发送方IP
	if (m_cChkSenderIp.GetCheck())
	{
		m_sCaptureFilter.bSrcIp = 1;
		m_cIpSender.GetAddress(m_sCaptureFilter.dwSrcIp);
	}
	else
	{
		m_sCaptureFilter.bSrcIp = 0;
	}

	// 接收方IP
	if (m_cChkTargetIp.GetCheck())
	{
		m_sCaptureFilter.bDstIp = 1;
		m_cIpTarget.GetAddress(m_sCaptureFilter.dwDstIp);
	}
	else
	{
		m_sCaptureFilter.bDstIp = 0;
	}

	m_sCaptureFilter.dwProtocol = dwCapFilter;
	m_pOwnerDlg->SetCapFilter(m_sCaptureFilter);
	CDialogEx::OnOK();
}


void CCapfilterDlg::OnClickedCheckTcp()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwState = m_cTcp.GetCheck();
	if (dwState != BST_CHECKED)
		dwState = m_cUdp.GetCheck();
	m_cChkSenderUdp.EnableWindow(dwState);
	m_cChkTargetUdp.EnableWindow(dwState);
	m_cEdtSenderUdp.SetReadOnly(!dwState);
	m_cEdtTargetUdp.SetReadOnly(!dwState);
}


void CCapfilterDlg::OnClickedCheckUdp()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwState = m_cUdp.GetCheck();
	if (dwState != BST_CHECKED)
		dwState = m_cTcp.GetCheck();
	m_cChkSenderUdp.EnableWindow(dwState);
	m_cChkTargetUdp.EnableWindow(dwState);
	m_cEdtSenderUdp.SetReadOnly(!dwState);
	m_cEdtTargetUdp.SetReadOnly(!dwState);
}