#include "stdafx.h"
#include "Protocols.h"
#include "GlobalVar.h"
#include "XSnifferDlg.h"
#include "ShowThread.h"
#include <vector>
#include <string>
#include <iterator>
using namespace std;


CShowThread::CShowThread(DWORD dwTcp, DWORD dwUdp, 
	DWORD dwArp, DWORD dwIgmp, DWORD dwIcmp, CXSnifferDlg * pDlg)
{
	m_bSafeExit = FALSE;
	m_bThreadRolling = FALSE;

	m_pDlg = pDlg;
	m_dwTcp = dwTcp;
	m_dwUdp = dwUdp;
	m_dwArp = dwArp;
	m_dwIgmp = dwIgmp;
	m_dwIcmp = dwIcmp;

	m_pListCtrl = m_pDlg->GetPacketListWnd();
	m_pCountBar = m_pDlg->GetPacketNumBarWnd();
}


CShowThread::~CShowThread()
{
}

INT CShowThread::Run()
{
	return 0;
}

BOOL CShowThread::InitInstance()
{
	return 0;
}

INT CShowThread::ExitInstance()
{
	return 0;
}
