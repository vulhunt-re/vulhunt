#include "decompiler_annot.hh"
#include "bridge.hh"

#include <iostream>
#include <climits>
#include <map>
#include <pugixml.hpp>
#include <sstream>
#include <string>

#include "funcdata.hh"

using Funcdata = ghidra::Funcdata;
using FuncCallSpecs = ghidra::FuncCallSpecs;
using HighVariable = ghidra::HighVariable;
using PcodeOp = ghidra::PcodeOp;
using MapIterator = ghidra::MapIterator;
using ScopeLocal = ghidra::ScopeLocal;
using Symbol = ghidra::Symbol;
using SymbolEntry = ghidra::SymbolEntry;
using Varnode = ghidra::Varnode;

using LowlevelError = ghidra::LowlevelError;

using uintm = ghidra::uintm;

struct ParseCodeXMLContext {
  Funcdata *func;
  std::map<uintm, PcodeOp *> ops;
  std::map<unsigned long long, Varnode *> varnodes;
  std::map<unsigned long long, Symbol *> symbols;

  explicit ParseCodeXMLContext(Funcdata *func) : func(func) {
    for (auto it = func->beginOpAll(); it != func->endOpAll(); it++) {
      ops[it->first.getTime()] = it->second;
    }

    for (auto it = func->beginLoc(); it != func->endLoc(); it++) {
      varnodes[(*it)->getCreateIndex()] = *it;
    }

    ScopeLocal *mapLocal = func->getScopeLocal();
    MapIterator iter = mapLocal->begin();
    MapIterator enditer = mapLocal->end();

    for (; iter != enditer; ++iter) {
      const SymbolEntry *entry = *iter;
      Symbol *sym = entry->getSymbol();
      symbols[sym->getId()] = sym;
    }
  }
};

#define ANNOTATOR_PARAMS                                                       \
  pugi::xml_node node, ParseCodeXMLContext *ctx, DecompilerAnnotationDB &mapper
#define ANNOTATOR [](ANNOTATOR_PARAMS) -> void

void AnnotateOpref(ANNOTATOR_PARAMS) {
  pugi::xml_attribute attr = node.attribute("opref");
  if (attr.empty())
    return;
  unsigned long long opref = attr.as_ullong(ULLONG_MAX);
  if (opref == ULLONG_MAX)
    return;
  auto opit = ctx->ops.find((uintm)opref);
  if (opit == ctx->ops.end())
    return;
  auto op = opit->second;

  mapper.annotate_offset(op->getAddr().getOffset());
}

void AnnotateCall(ANNOTATOR_PARAMS) {
  pugi::xml_attribute attr = node.attribute("opref");
  if (attr.empty())
    return;
  unsigned long long opref = attr.as_ullong(ULLONG_MAX);
  if (opref == ULLONG_MAX)
    return;
  auto opit = ctx->ops.find((uintm)opref);
  if (opit == ctx->ops.end())
    return;
  auto op = opit->second;

  if (op->code() == ghidra::CPUI_CALLIND) {
    // We assume we have discovered a block like:
    //
    // .text:000090E4                 LDR     R2, =(aSaxEntitydeclS+0x1E - 0x90F8) ; " %s)\n"
    // .text:000090E8                 MOV     R3, R5
    // .text:000090EC                 LDR     R0, [R4]
    // .text:000090F0                 ADD     R2, PC, R2      ; " %s)\n"
    // .text:000090F4                 MOV     R1, #1
    // .text:000090F8                 POP     {R4-R6,LR}
    // .text:000090FC                 B       __fprintf_chk ; 0x3114
    //  .plt:00003114                 ADR     R12, 0x311C
    //  .plt:00003118                 ADD     R12, R12, #0x19000
    //  .plt:0000311C                 LDR     PC, [R12,#(__fprintf_chk_ptr - 0x1C11C)]!
    //
    //  In this case, we will have the operation at 0x311c rewritten to be an indirect call;
    //  the call-site address we'd actually like to propagate here is via 0x90fc.
    //
    auto bl = op->getParent();
    auto ea = bl->getExitAddr();
    auto s = bl->getStop();

    if (bl->lastOp()->getAddr() != ea) {
      mapper.annotate_function_call(ea.getOffset());
    } else if (bl->lastOp()->getAddr() != s) {
      mapper.annotate_function_call(s.getOffset());
    }
  }

  mapper.annotate_function_call(op->getAddr().getOffset());
}

void AnnotateFunctionName(ANNOTATOR_PARAMS) {
  const char *func_name = node.child_value();
  if (!func_name)
    return;

  pugi::xml_attribute attr = node.attribute("opref");
  if (attr.empty()) {
    if (ctx->func->getName() == func_name) {
      mapper.annotate_function_name(rust::String(ctx->func->getName()),
                                    ctx->func->getAddress().getOffset());
      mapper.annotate_offset(ctx->func->getAddress().getOffset());
    }
    return;
  }

  unsigned long long opref = attr.as_ullong(ULLONG_MAX);
  if (opref == ULLONG_MAX) {
    return;
  }
  auto opit = ctx->ops.find((uintm)opref);
  if (opit == ctx->ops.end()) {
    return;
  }
  PcodeOp *op = opit->second;
  FuncCallSpecs *call_func_spec = ctx->func->getCallSpecs(op);
  if (call_func_spec) {
    mapper.annotate_function_name(
        rust::String(call_func_spec->getName()),
        call_func_spec->getEntryAddress().getOffset());
  }
}

void AnnotateCommentOffset(ANNOTATOR_PARAMS) {
  pugi::xml_attribute attr = node.attribute("off");
  if (attr.empty())
    return;
  unsigned long long off = attr.as_ullong(ULLONG_MAX);
  if (off == ULLONG_MAX)
    return;

  mapper.annotate_offset(off);
}

void AnnotateGlobalVariable(Symbol *symbol, Varnode *varnode,
                            DecompilerAnnotationDB &mapper) {
  if (symbol == nullptr) {
    return;
  }
  mapper.annotate_global_variable(rust::String(symbol->getName()),
                                  varnode->getOffset());
}

void AnnotateConstantVariable(Symbol *symbol, Varnode *varnode,
                              DecompilerAnnotationDB &mapper) {
  if (symbol == nullptr) {
    return;
  }
  mapper.annotate_constant(rust::String(symbol->getName()),
                           varnode->getOffset());
}

void AnnotateLocalVariable(Symbol *symbol, DecompilerAnnotationDB &mapper) {
  if (symbol == nullptr) {
    return;
  }
  if (symbol->getCategory() == 0) {
    mapper.annotate_function_parameter(symbol->getName());
  } else {
    mapper.annotate_local_variable(symbol->getName());
  }
}

void AnnotateVariable(ANNOTATOR_PARAMS) {
  pugi::xml_attribute attr = node.attribute("varref");
  pugi::xml_attribute opref_attr = node.attribute("opref");

  unsigned long long opref = opref_attr.as_ullong(ULLONG_MAX);

  if (opref == ULLONG_MAX)
    return;
  auto opit = ctx->ops.find((uintm)opref);
  if (opit == ctx->ops.end())
    return;
  auto op = opit->second;

  if (attr.empty()) {
    auto node_parent = node.parent();
    if (strcmp(node_parent.name(), "vardecl") == 0) {
      pugi::xml_attribute attributeSymbolId = node_parent.attribute("symref");
      unsigned long long symref = attributeSymbolId.as_ullong(ULLONG_MAX);
      Symbol *symbol = ctx->symbols[symref];
      AnnotateLocalVariable(symbol, mapper);
      mapper.annotate_offset(op->getAddr().getOffset());
    }
    return;
  }
  unsigned long long varref = attr.as_ullong(ULLONG_MAX);
  if (varref == ULLONG_MAX) {
    return;
  }
  auto varrefnode = ctx->varnodes.find(varref);
  if (varrefnode == ctx->varnodes.end()) {
    return;
  }
  Varnode *varnode = varrefnode->second;
  HighVariable *high;
  try {
    high = varnode->getHigh();
  } catch (const LowlevelError &e) {
    return;
  }
  if (high->isPersist() && high->isAddrTied()) {
    AnnotateGlobalVariable(high->getSymbol(), varnode, mapper);
  } else if (high->isConstant() && high->getType()->getMetatype() == ghidra::TYPE_PTR) {
    AnnotateConstantVariable(high->getSymbol(), varnode, mapper);
  } else if (!high->isPersist()) {
    AnnotateLocalVariable(high->getSymbol(), mapper);
  }
  mapper.annotate_offset(op->getAddr().getOffset());
}

static const std::map<std::string, std::vector<void (*)(ANNOTATOR_PARAMS)>>
    annotators = {
        {"statement", {AnnotateOpref}},   {"funccall", {AnnotateCall}},
        {"op", {AnnotateOpref}},          {"comment", {AnnotateCommentOffset}},
        {"variable", {AnnotateVariable}}, {"funcname", {AnnotateFunctionName}}};

static void ParseNode(pugi::xml_node node, ParseCodeXMLContext *ctx,
                      std::ostream &stream, DecompilerAnnotationDB &mapper) {
  if (node.type() == pugi::xml_node_type::node_pcdata) {
    stream << node.value();
    return;
  }

  mapper.open_scope(stream.tellp());

  if (strcmp(node.name(), "break") == 0) {
    stream << "\n";
    stream << std::string(node.attribute("indent").as_uint(0), ' ');
  } else {
    auto it = annotators.find(node.name());
    if (it != annotators.end()) {
      auto &callbacks = it->second;
      auto start_pos = stream.tellp();
      for (auto &callback : callbacks) {
        callback(node, ctx, mapper);
      }
    }
  }

  for (pugi::xml_node child : node) {
    ParseNode(child, ctx, stream, mapper);
  }

  mapper.close_scope(stream.tellp());
}

void ParseCodeXML(Funcdata *func, DecompilerAnnotationDB &mapper, const char *xml) {
  pugi::xml_document doc;
  if (!doc.load_string(xml, pugi::parse_default | pugi::parse_ws_pcdata)) {
    return;
  }

  std::stringstream ss;

  ParseCodeXMLContext ctx(func);
  ParseNode(doc.child("function"), &ctx, ss, mapper);

  mapper.annotate_source(ss.str());
}

std::string FormatXML(const char *xml) {
  pugi::xml_document doc;
  if (!doc.load_string(xml, pugi::parse_default | pugi::parse_ws_pcdata)) {
    throw std::runtime_error("invalid decompiler output");
  }

  std::stringstream ss;

  doc.save(ss);

  return ss.str();
}
