#pragma once


// CCapfilterDlg 对话框

class CCapfilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCapfilterDlg)

public:
	CCapfilterDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CCapfilterDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_CAPFILTER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
