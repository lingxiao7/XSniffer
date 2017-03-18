
// XSnifferDlg.h : 头文件
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

// CXSnifferDlg 对话框
class CXSnifferDlg : public CDialogEx
{
// 构造
public:
	CXSnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_XSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:

	CMenu m_Menu;

	/* 相关控件 */
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

	/* 网卡设备 */
	pcap_if_t * m_pAllDevs;

	/* 包流量统计 */
	DWORD m_dwTcp;
	DWORD m_dwUdp;
	DWORD m_dwArp;
	DWORD m_dwIgmp;
	DWORD m_dwIcmp;

	/* 相关线程 */
	// 抓包线程
	CCapThread  * m_tCapThread;
	// 绘制ListView线程
	CShowThread * m_tShowThread;

	/* 抓包相关 */
	// 选择网卡
	INT m_nCurAdapter;
	CString m_strCurAdapter;
	// 过滤器
	CaptureFilter m_sCapFilter;
	// 正在抓包
	BOOL m_bCurCapture;

public:
	// 初始化控件
	BOOL InitControls();
	// 初始化WinPcap
	BOOL InitWinPcap();
	void UpdatePackNum(DWORD dwTcp, DWORD dwUdp,
		DWORD dwArp, DWORD dwIgmp, DWORD dwIcmp);

	CListCtrl	* GetPacketListWnd();
	CStatic		* GetPacketNumBarWnd();
	pcap_if_t	* GetAllDevs();

	void SetCurAdapter(int nIndex);
	void SetCurAdapter(CString strInfo);
	void SetCapFilter(CaptureFilter sCapFilter);

	// 反初始化WinPcap
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

	// 更新TreeView数据
	void UpdateTreeViewData(DWORD dwIndex);
};
