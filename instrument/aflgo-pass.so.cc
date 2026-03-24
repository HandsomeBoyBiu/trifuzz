/*
   aflgo - LLVM instrumentation pass
   ---------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_LLVM_PASS

#include "../afl-2.57b/config.h"
#include "../afl-2.57b/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

cl::opt<std::string> TmpDir(
    "tmpdir",
    cl::desc("Directory where temporary files are generated."),
    cl::value_desc("tmpdir"));

#define ENABLE_EXIT_INSTR 0

std::set<std::string> fname_wl = {"main", "llvm"};

namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static void getDebugLoc(
  Function* Func,
  std::string& Filename,
  unsigned& Line
) {
  if (DISubprogram* SP = Func->getSubprogram()) {
    if (SP->describes(Func)) {
      std::string tFile = SP->getFile()->getFilename().str();
      std::size_t pos = tFile.find_last_of("/\\");
      Filename = tFile.substr(pos + 1);
      Line = SP->getLine();
    }
  }
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

bool AFLCoverage::runOnModule(Module &M) {

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::map<std::string, int> bb_to_potential;
  std::set<std::string> exit_instr_func_linfo;
  std::set<std::string> exit_instr_func_names;
  std::set<std::string> bb_targets;
  std::vector<std::string> basic_blocks;
  std::vector<std::string> potential_basic_blocks;
  std::set<std::string> critical_basic_blocks;

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line);
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty() && !TmpDir.empty()) {

    std::ifstream cf(DistanceFile);
    std::ifstream pf(TmpDir + "//potential.bb.txt");
    std::ifstream cff_str(TmpDir + "//concolic.execution.instr.fname.txt");    // exit() instr func (not instr)
    std::ifstream cff_linfo(TmpDir + "//concolic.execution.instr.txt");    // exit() instr func (not instr)
    std::ifstream bb_targets_fn(TmpDir + "//BBtargets.txt");   // target basic blocks (for distance reaching metric)
    std::ifstream critical_bb_fn(TmpDir + "//potential.bb.txt");   // critical basic blocks

    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

    if (pf.is_open()) {

      std::string line;
      while (getline(pf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_potential = atoi(line.substr(pos + 1, line.length()).c_str());

        bb_to_potential.emplace(bb_name, bb_potential);

      }
      pf.close();

    } else {
      FATAL("Unable to find %s.", (TmpDir + "//potential.bb.txt").c_str());
      return false;
    }

    if (critical_bb_fn.is_open()) {

      std::string line;
      while (getline(critical_bb_fn, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        critical_basic_blocks.insert(bb_name);

      }
      critical_bb_fn.close();

    } else {
      FATAL("Unable to find %s.", (TmpDir + "//potential.bb.txt [critical]").c_str());
      return false;
    }

    if (cff_linfo.is_open()) {

      std::string line;
      while (getline(cff_linfo, line)) {

        exit_instr_func_linfo.insert(line);

      }
      cff_linfo.close();

    } else {
      FATAL("Unable to find %s.", (TmpDir + "//cf.func.linfo.txt").c_str());
      return false;
    }

    if (cff_str.is_open()) {

      std::string line;
      while (getline(cff_str, line)) {

        exit_instr_func_names.insert(line);

      }
      cff_str.close();

    } else {
      FATAL("Unable to find %s.", (TmpDir + "//cf.func.str.txt").c_str());
      return false;
    }

    if (bb_targets_fn.is_open()) {

      std::string line;
      while (getline(bb_targets_fn, line)) {

        bb_targets.insert(line);

      }
      bb_targets_fn.close();

    } else {
      FATAL("Unable to find %s.", (TmpDir + "//BBtargets.txt").c_str());
      return false;
    }
    bb_targets.erase("");
    bb_targets.erase("\n");

  }

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream allcallinsts(OutDirectory + "/allcallinsts.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {

      bool has_BBs = false;
      std::string funcName = F.getName().str();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) {
          getDebugLoc(&I, filename, line);

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;

          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1);

          if (bb_name.empty()) 
            bb_name = filename + ":" + std::to_string(line);
          
          if (!is_target) {
            for (auto &target : targets) {
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);

              std::size_t pos = target.find_last_of(":");
              std::string target_file = target.substr(0, pos);
              unsigned int target_line = atoi(target.substr(pos + 1).c_str());

              if (!target_file.compare(filename) && target_line == line)
                is_target = true;

            }
          }

          if (auto *c = dyn_cast<CallInst>(&I)) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            if (auto *CalledF = c->getCalledFunction()) {
              if (!isBlacklisted(CalledF))
                bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
              if (CalledF->getName().str() != "llvm.dbg.declare" && CalledF->getName().str() != "llvm.dbg.value") {
                allcallinsts << filename + "," + std::to_string(line) << " " << CalledF->getName().str() << "\n";
              }
            }
          }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }
    }

  } else {
    int instCounter = 1;

    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
    ConstantInt *TargetReachedLoc = ConstantInt::get(LargestType, MAP_SIZE + 2 * 8);
    ConstantInt *PotentialSum = ConstantInt::get(LargestType, MAP_SIZE + 3 * 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
    ConstantInt *TargetReachedLoc = ConstantInt::get(LargestType, MAP_SIZE + 2 * 4);
    ConstantInt *PotentialSum = ConstantInt::get(LargestType, MAP_SIZE + 3 * 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *CriticalMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__trifuzz_critical_bb_map_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    // exit() declaration
    llvm::FunctionCallee exitFunc = M.getOrInsertFunction(
        "exit",
        llvm::Type::getVoidTy(M.getContext()),    // 返回类型 void
        llvm::Type::getInt32Ty(M.getContext())    // 参数 int
    );

    for (auto &F : M) {

      int distance = -1;

      bool is_exit_instr_func = false;
#if ENABLE_EXIT_INSTR
      // 1. function name
      std::string funcName = F.getName().str();
      // 如果没找到函数则设置flag为true
      // 如果在白名单里面则不设置flag
      if (exit_instr_func_names.find(funcName) == exit_instr_func_names.end()) {
        is_exit_instr_func = true;
        for (const auto& wl_item : fname_wl) {
          if (funcName.find(wl_item) != std::string::npos) {
            is_exit_instr_func = false;
            break;
          }
        }
      }
      
      if (is_exit_instr_func) {
        errs() << "Drop function: " << funcName << "\n";
      } else {
        errs() << "Keep function: " << funcName << "\n";
      }
      
#endif  // ENABLE_EXIT_INSTR

      for (auto &BB : F) {

        distance = -1;
        bool is_target_bb = false;
        bool is_critical_bb = false;
        int potential = -1;

        if (is_aflgo) {

          std::string bb_name;
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            break;
          }

          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            std::string full_bb_name = filename + ":" + std::to_string(line);
            if (bb_targets.find(full_bb_name) != bb_targets.end()) {
              is_target_bb = true;
              break;
            }
          }

          for (std::map<std::string, int>::iterator it = bb_to_potential.begin(); it != bb_to_potential.end(); ++it) {
            if (it->first.compare(bb_name) == 0) {
              potential = it->second;
              break;
            }
          }

          for (const auto& critical_bb : critical_basic_blocks) {
            if (critical_bb.compare(bb_name) == 0) {
              is_critical_bb = true;
              break;
            }
          }

          if (is_exit_instr_func) {
            llvm::IRBuilder<> IRB(&*BB.getFirstInsertionPt()); 
            IRB.CreateCall(exitFunc, {llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), 1)}); 
            IRB.CreateUnreachable();
          }

          if (!bb_name.empty()) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }
          }
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);

          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        if (potential >= 0) {

          SAYF(cGRN "[+] Potential instrumented for function %s: %d\n" cRST,
               F.getName().str().c_str(), potential);

          ///* TODO : better way to resolve this issue? */
          //int potential_to_instr = potential;
          //if (potential_to_instr == 0) {
          //  potential_to_instr = -1; 
          //}
          ConstantInt *PotentialVal =
              ConstantInt::get(LargestType, (unsigned) potential);

          Value* PotentialCntPtr = IRB.CreateBitCast(
            IRB.CreateGEP(MapPtr, PotentialSum), LargestType->getPointerTo()
          );
          LoadInst* PotentialSumLoadInst = IRB.CreateLoad(PotentialCntPtr);
          PotentialSumLoadInst->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value* IncrPotential = IRB.CreateAdd(PotentialSumLoadInst, PotentialVal);
          IRB.CreateStore(IncrPotential, PotentialCntPtr)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        if (is_critical_bb) {

          SAYF(cYEL "[+] Critical BB instrumented for function %s\n" cRST,
               F.getName().str().c_str());

          // LLVM IR 插桩，__trifuzz_critical_bb_map_ptr[instCounter] ++; instCounter++
          ConstantInt *CriticalValLoc = ConstantInt::get(Int32Ty, (unsigned) instCounter);
          LoadInst *CriticalMapPtrLoad = IRB.CreateLoad(CriticalMapPtr);
          CriticalMapPtrLoad->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value* CriticalBBPtr = IRB.CreateGEP(CriticalMapPtrLoad, CriticalValLoc);
          IRB.CreateStore(ConstantInt::get(Int8Ty, 1), CriticalBBPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          instCounter++;

        }

        if (is_target_bb || distance == 0) {
          /* Mark target reached at shm[MAPSIZE + 2*(4 or 8)] */

          Value *TargetReachedPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, TargetReachedLoc), LargestType->getPointerTo());
          IRB.CreateStore(One, TargetReachedPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        }

        inst_blocks++;

      }
    }
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
