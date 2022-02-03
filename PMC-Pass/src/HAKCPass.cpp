/**
 * @brief HAKC Analysis and Transformation pass
 * @file HAKCPass.cpp
 */

#include "HAKCPass.h"
#include "HAKCSymbolGenerator.h"
#include "HAKCTypeIdentifier.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace hakc {
    std::error_code getCorrespondingPathInBuildDirectory(StringRef
    pathToSourceFile, SmallVectorImpl<char> &result) {
        std::error_code err;
        SmallVector<char> buildPath;
        SmallVector<char> sourcePath;
        SmallVector<char> kernelRootPath;
        const char* src_root;

        err = sys::fs::real_path(pathToSourceFile, sourcePath, true);
        if (err) {
            return err;
        }
        err = sys::fs::current_path(buildPath);
        if (err) {
            return err;
        }
        StringRef pathString(sourcePath.data(), sourcePath.size());
        StringRef currPathString(buildPath.data(), buildPath.size());
        if(pathString.startswith(currPathString)) {
            result.append(pathToSourceFile.begin(), pathToSourceFile.end());
            return std::error_code(0, std::generic_category());
        }

        src_root = std::getenv("abs_srctree");
        if (!src_root) {
            return std::error_code(-1, std::generic_category());
        }

        err = sys::fs::real_path(src_root, kernelRootPath, true);
        if (err) {
            return err;
        }

        unsigned diff_start;
        for (diff_start = 0;
             diff_start < std::min(kernelRootPath.size(), sourcePath.size());
             diff_start++) {
            if (sourcePath[diff_start] != kernelRootPath[diff_start]) {
                break;
            }
        }

        result.append(buildPath.begin(), buildPath.end());
        result.append(sourcePath.begin() + diff_start,
                           sourcePath.end());

        return std::error_code(0, std::generic_category());
    }

    std::error_code getRelativeSourcePath(StringRef relativeSourcePath,
                                          SmallVectorImpl<char> &result) {
        SmallVector<char> sourcePath;
        SmallVector<char> buildPath;

        std::error_code err;
        std::string relativePath;

        err = sys::fs::real_path(relativeSourcePath, sourcePath, true);
        if (err) {
            return err;
        }

        err = getCorrespondingPathInBuildDirectory(relativeSourcePath,
                                                   buildPath);
        if (err) {
            return err;
        }

        for (auto srcIt = sourcePath.rbegin(), buildIt = buildPath.rbegin();
             srcIt != sourcePath.rend() && buildIt != buildPath.rend(); srcIt++,
                     buildIt++) {
            if (*srcIt != *buildIt) {
                break;
            }
            relativePath += *srcIt;
        }

        std::reverse(relativePath.begin(), relativePath.end());
        if(sys::path::is_separator(*relativePath.begin())) {
            relativePath.erase(relativePath.begin());
        }

        result.append(relativePath.begin(), relativePath.end());
        return std::error_code(0, std::generic_category());
    }


    bool runDataAccessGraphAnalysis(Module &M) {
        SmallVector<char> buildPath;
        HAKCTypeIdentifier typeIdentifier(M);
        std::string outFileName;
        if (getCorrespondingPathInBuildDirectory(M.getSourceFileName(),
                                                 buildPath)) {
            errs() << "Could not get corresponding path in the build "
                      "directory\n";
            throw std::exception();
        }

        for (unsigned i = 0; i <
                             buildPath.size() - sys::path::extension(
                                     M.getSourceFileName()).size(); i++) {
            outFileName += buildPath[i];
        }
        outFileName += ".dag.yml";

        std::error_code err;
        raw_fd_ostream out(outFileName, err);
        if (!err) {
            typeIdentifier.outputTypes(out);
            out.close();
        } else {
            errs() << "Failed to open " << outFileName << "\n";
            throw std::exception();
        }
        return false;
    }

    bool runSymbolGeneration(Module &M) {
        HAKCSymbolGenerator symbolGenerator(M);
        return false;
    }

    bool runCompartmentalization(Module &M) {
        HAKCSystemInformation compartmentalizationInformation(M);

        HAKCModuleTransformation transformation(M,
                                                compartmentalizationInformation);
        transformation.performTransformations();
        if (transformation.isCompartmentalized()) {
            errs() << "Total Data Checks: "
                   << transformation.totalDataChecks << "\n"
                   << "Total Code Checks: "
                   << transformation.totalCodeChecks << "\n"
                   << "Total Transfers:   "
                   << transformation.totalTransfers
                   << "\n";
        }

        // if (transformation.isModuleTransformed()) {
        //     M.print(errs(), nullptr);
        // }
        return transformation.isModuleTransformed();
    }

    struct HAKCPass : public ModulePass {
        static char ID;
        const std::string HAKC_ENV_VAR = "HAKC_ANALYSIS";

        HAKCPass() : ModulePass(ID) {}

        const std::vector<std::pair<std::string,
                std::function<bool(Module &)>>> available_options = {
                        {"dag", runDataAccessGraphAnalysis},
                        {"symbols", runSymbolGeneration},
                        {"compartmentalize", runCompartmentalization}};

        bool runOnModule(Module &M) override {
	    const char *preload = std::getenv(HAKC_ENV_VAR.c_str());
            if (preload) {
                for (auto opt: available_options) {
                    if (opt.first == preload) {
                        return opt.second(M);
                    }
                }
                errs() << "WARNING: "
                       << HAKC_ENV_VAR
                       << " was set to " << preload
                       << " which is invalid.  No HAKC analysis was performed\n";
                return false;
            } else {
                errs() << "WARNING: "
                       << HAKC_ENV_VAR
                       << " is not set! No HAKC analysis was performed!\n";
                return false;
            }
        }
    };

}// namespace hakc

char hakc::HAKCPass::ID = 0;

static void registerPMCPass(const llvm::PassManagerBuilder &,
                            llvm::legacy::PassManagerBase &PM) {
    PM.add(new hakc::HAKCPass());
}

static llvm::RegisterStandardPasses
        RegisterMyPass(llvm::PassManagerBuilder::EP_ScalarOptimizerLate,
                       registerPMCPass);

static RegisterPass<hakc::HAKCPass>
        X("HAKCPass", "HAKC Compartmentalization Pass",
          false,// This pass doesn't modify the CFG => true
          false // This pass is not a pure analysis pass => false
);
