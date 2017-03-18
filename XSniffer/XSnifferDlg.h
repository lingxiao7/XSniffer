
// XSnifferDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include "AdaptersDlg.h"
#include "afxwin.h"
#include "CapFilterDlg.h"
#include "CapThread.h"
#include "ShowThread.h"
#include "resource.h"
#include "hexedit.h"

// CXSnifferDlg �Ի���
class CXSnifferDlg : public CDialogEx
{
// ����
public:
	CXSnifferDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_XSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:

	CMenu m_Menu;

	/* ��ؿؼ� */
	// Packets List View.
	CListCtrl m_cPacketsList;
	// Packets Tree View
	CTreeCtrl m_cPacketsTree;
	// Packets' Details in HexView
	CHexEdit m_cHexView;
	// Packets Status.
	CStatic m_cPacketNumBar;
	// Choose a Adapter to Capture Packets.
	CStatic m_cPacketAdapter;

	/* �����豸 */
	pcap_if_t * m_pAllDevs;

	/* ������ͳ�� */
	DWORD m_dwTcp;
	DWORD m_dwUdp;
	DWORD m_dwArp;
	DWORD m_dwIgmp;
	DWORD m_dwIcmp;

	/* ����߳� */
	// ץ���߳�
	CCapThread  * m_tCapThread;
	// ����ListView�߳�
	CShowThread * m_tShowThread;

	/* ץ����� */
	// ѡ������
	INT m_nCurAdapter;
	CString m_strCurAdapter;
	// ������
	CaptureFilter m_sCapFilter;
	// ����ץ��
	BOOL m_bCurCapture;

public:
	// ��ʼ���ؼ�
	BOOL InitControls();
	// ��ʼ��WinPcap
	BOOL InitWinPcap();
	void UpdatePackNum(DWORD dwTcp, DWORD dwUdp,
		DWORD dwArp, DWORD dwIgmp, DWORD dwIcmp);

	CListCtrl	* GetPacketListWnd();
	CStatic		* GetPacketNumBarWnd();
	pcap_if_t	* GetAllDevs();

	void SetCurAdapter(int nIndex);
	void SetCurAdapter(CString strInfo);
	void SetCapFilter(CaptureFilter sCapFilter);

	// ����ʼ��WinPcap
	void UnInitWinPcap();
	afx_msg void OnFileQuit();
	afx_msg void OnClose();
	afx_msg void OnOptSeldev();
	afx_msg void OnAbout();
	afx_msg void OnOptSetcapfilter();
//	afx_msg void OnOptStart();
	afx_msg void OnOptStartcap();
	afx_msg void OnOptStopcap();
	afx_msg void OnFileClose();
	afx_msg void OnClickListPackets(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnSelchangedTreePackets(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnDeleteitemTreePackets(NMHDR *pNMHDR, LRESULT *pResult);

	// ����TreeView����
	void UpdateTreeViewData(DWORD dwIndex);
};
