
// XSniffer.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CXSnifferApp: 
// �йش����ʵ�֣������ XSniffer.cpp
//

class CXSnifferApp : public CWinApp
{
public:
	CXSnifferApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CXSnifferApp theApp;