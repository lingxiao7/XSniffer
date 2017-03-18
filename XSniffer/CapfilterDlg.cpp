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

CCapfilterDlg::~CCapfilterDlg()
{
}

void CCapfilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCapfilterDlg, CDialogEx)
END_MESSAGE_MAP()


// CCapfilterDlg 消息处理程序
