#pragma once


// CCapfilterDlg �Ի���

class CCapfilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCapfilterDlg)

public:
	CCapfilterDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CCapfilterDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_CAPFILTER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
};
