#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "CommonDef.h"
#include "XSnifferDlg.h"

class CXSnifferDlg;
// CCapfilterDlg �Ի���

class CCapfilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCapfilterDlg)

public:
	CCapfilterDlg(CWnd* pParent = NULL);   // ��׼���캯��
	CCapfilterDlg(CXSnifferDlg *, CaptureFilter , CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CCapfilterDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_CAPFILTER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP();
private:
	// Arpѡ��ť
	CButton m_cArp;
	// ICMPѡ��ť
	CButton m_cIcmp;
	// IGMPѡ��ť
	CButton m_cIgmp;
	// Tcpѡ��ť
	CButton m_cTcp;
	// UDPѡ��ť
	CButton m_cUdp;
	// �Ƿ����÷��ͷ�IP
	CButton m_cChkSenderIp;
	// �Ƿ����ý��շ�IP
	CButton m_cChkTargetIp;
	// ���ͷ�IP
	CIPAddressCtrl m_cIpSender;
	// ���շ�IP
	CIPAddressCtrl m_cIpTarget;
	// �Ƿ����÷��ͷ�UDP�˿�
	CButton m_cChkSenderUdp;
	// �Ƿ����ý��շ�UDP�˿�
	CButton m_cChkTargetUdp;
	// ���ͷ�UDP�˿�
	CEdit m_cEdtSenderUdp;
	// ���շ�UDP�˿�
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
