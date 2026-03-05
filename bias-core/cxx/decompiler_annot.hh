#pragma once

#include "bridge.hh"
#include "decompiler.hh"

namespace ghidra {
class Funcdata;
}; // namespace ghidra

using Funcdata = ghidra::Funcdata;

std::string FormatXML(const char *xml);
void ParseCodeXML(Funcdata *func, DecompilerAnnotationDB &mapper,
                  const char *xml);
