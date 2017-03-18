#pragma once
#include "afxwin.h"
#include "XSnifferDlg.h"
#include "pcap.h"

class CXSnifferDlg;

// CAdaptersDlg 对话框
class CAdaptersDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAdaptersDlg)

public:
	CAdaptersDlg(CWnd* pParent = NULL);   // 标准构造函数
	CAdaptersDlg(CXSnifferDlg *pOwnerDlg, CWnd* pParent = NULL);
	virtual ~CAdaptersDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_ADAPTERS };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()


public:
	virtual BOOL OnInitDialog();
//	afx_msg void OnLbnSelchangeListAdapters();

private:
	CXSnifferDlg *m_pOwnerDlg;

	// 网卡列表List View
	CListBox m_cAdapterList;


	/* 打印所有可用信息 */
	void ifprint(pcap_if_t *d);
	char * iptos(u_long in);
	char * CAdaptersDlg::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
public:
	afx_msg void OnLbnDblclkListAdapters();
};
