#pragma once
#include "afxwin.h"
#include "XSnifferDlg.h"
#include "pcap.h"

class CXSnifferDlg;

// CAdaptersDlg �Ի���
class CAdaptersDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAdaptersDlg)

public:
	CAdaptersDlg(CWnd* pParent = NULL);   // ��׼���캯��
	CAdaptersDlg(CXSnifferDlg *pOwnerDlg, CWnd* pParent = NULL);
	virtual ~CAdaptersDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_ADAPTERS };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()


public:
	virtual BOOL OnInitDialog();
//	afx_msg void OnLbnSelchangeListAdapters();

private:
	CXSnifferDlg *m_pOwnerDlg;

	// �����б�List View
	CListBox m_cAdapterList;


	/* ��ӡ���п�����Ϣ */
	void ifprint(pcap_if_t *d);
	char * iptos(u_long in);
	char * CAdaptersDlg::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
public:
	afx_msg void OnLbnDblclkListAdapters();
};
