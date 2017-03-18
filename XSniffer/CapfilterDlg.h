#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "CommonDef.h"
#include "XSnifferDlg.h"

class CXSnifferDlg;
// CCapfilterDlg 对话框

class CCapfilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCapfilterDlg)

public:
	CCapfilterDlg(CWnd* pParent = NULL);   // 标准构造函数
	CCapfilterDlg(CXSnifferDlg *, CaptureFilter , CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CCapfilterDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_CAPFILTER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP();
private:
	// Arp选择按钮
	CButton m_cArp;
	// ICMP选择按钮
	CButton m_cIcmp;
	// IGMP选择按钮
	CButton m_cIgmp;
	// Tcp选择按钮
	CButton m_cTcp;
	// UDP选择按钮
	CButton m_cUdp;
	// 是否设置发送方IP
	CButton m_cChkSenderIp;
	// 是否设置接收方IP
	CButton m_cChkTargetIp;
	// 发送方IP
	CIPAddressCtrl m_cIpSender;
	// 接收方IP
	CIPAddressCtrl m_cIpTarget;
	// 是否设置发送方UDP端口
	CButton m_cChkSenderUdp;
	// 是否设置接收方UDP端口
	CButton m_cChkTargetUdp;
	// 发送方UDP端口
	CEdit m_cEdtSenderUdp;
	// 接收方UDP端口
	CEdit m_cEdtTargetUdp;
private:
	CXSnifferDlg *m_pOwnerDlg;
	CaptureFilter m_sCaptureFilter;
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnClickedCheckTcp();
	afx_msg void OnClickedCheckUdp();
	virtual BOOL OnInitDialog();
};
