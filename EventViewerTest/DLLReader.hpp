#ifndef DLLREADER_HPP_
#define DLLREADER_HPP_

#include <Windows.h>
#include <stdio.h>
#include <unordered_map>
#include <sstream>
#include <iostream>

void ProcessBlock(MESSAGE_RESOURCE_DATA* data, MESSAGE_RESOURCE_BLOCK* block, std::unordered_map<DWORD, std::string> &map)
{
   MESSAGE_RESOURCE_ENTRY* entry = (MESSAGE_RESOURCE_ENTRY*)((unsigned char*)data + block->OffsetToEntries);
   for (DWORD id = block->LowId; id <= block->HighId; id++)
   {
      //printf("%lu, %ls", id, entry->Text);
      std::string str;
      for (int i = 0; i < entry->Length; i += 2)
      {
         str += entry->Text[i];
      }
      map[id] = str.c_str();
      entry = (MESSAGE_RESOURCE_ENTRY*)((unsigned char*)entry + entry->Length);
   }
}

bool readDLL(std::unordered_map<DWORD, std::string> &map)
{
   //HMODULE hMod = LoadLibrary(L"C:\\Users\\osele\\Desktop\\MpEvMsg.dll");
   HMODULE hMod = LoadLibraryEx(L"C:\\Program Files\\Windows Defender\\MpEvMsg.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
   if (hMod == NULL) {
      DWORD status = GetLastError();

      return 1;
   }

   HRSRC hRsrc = FindResource(hMod, MAKEINTRESOURCE(1), RT_MESSAGETABLE);
   if (hRsrc == NULL)
   {
      return 1;
   }

   HGLOBAL hGlobal = LoadResource(hMod, hRsrc);
   if (hGlobal == NULL)
   {
      return 1;
   }

   MESSAGE_RESOURCE_DATA* data = (MESSAGE_RESOURCE_DATA*)LockResource(hGlobal);
   if (data == NULL)
   {
      return 1;
   }

   for (DWORD block = 0; block < data->NumberOfBlocks; block++)
   {
      ProcessBlock(data, &data->Blocks[block], map);
   }

   return 0;
}


#endif