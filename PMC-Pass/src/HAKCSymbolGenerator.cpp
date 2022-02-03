//
// Created by derrick on 9/9/21.
//

#include "HAKCSymbolGenerator.h"
#include "HAKC-defs.h"
#include "HAKCPass.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"

#include <iostream>


LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::FileSymbols)

using namespace llvm;

template<>
struct yaml::MappingTraits<hakc::FileSymbols> {
    static void mapping(yaml::IO &io, hakc::FileSymbols &info) {
        io.mapRequired("FILE", info.file);
        io.mapOptional("FUNCTIONS", info.functions);
        io.mapOptional("GLOBAL_VARIABLES", info.globals);
    }
};

namespace hakc {
    HAKCSymbolGenerator::HAKCSymbolGenerator(Module &M) : M(M),
                                                          definedFunctions(),
                                                          definedGlobals() {
        gatherFunctions();
        gatherGlobals();
        output();
    }

    void HAKCSymbolGenerator::gatherFunctions() {
        for (auto &F: M.getFunctionList()) {
            /* TODO: Add more checks here for inclusion in list */
            if (F.isIntrinsic() || F.size() == 0) {
                continue;
            } else if (F.getName().contains(outside_transfer_prefix)) {
                continue;
            }

            definedFunctions.insert(&F);
        }
    }

    void HAKCSymbolGenerator::gatherGlobals() {
        for (auto &G: M.getGlobalList()) {
            /* TODO: Add more checks for inclusion in list */
            if (!G.hasInitializer() || G.isExternallyInitialized()) {
                continue;
            }

            definedGlobals.insert(&G);
        }
    }

    void HAKCSymbolGenerator::output() {
        /* Open <C file name>.yml in the same directory as the .o file. This
         * code relies on the fact that the Linux build system changes the
         * current directory to the build directory */
        SmallVector<char> buildPath;
        SmallVector<char> relativePath;
        std::string yamlpath;
        std::string relativeSourcePath;

        if (getCorrespondingPathInBuildDirectory(M.getSourceFileName(),
                                                 buildPath)) {
            errs() << "Could not get corresponding path in the build "
                      "directory\n";
            throw std::exception();
        }

        for (unsigned i = 0; i <
                             buildPath.size() - sys::path::extension(
                                     M.getSourceFileName()).size(); i++) {
            yamlpath += buildPath[i];
        }
        yamlpath += ".symbols.yml";
//        errs() << "Writing to " << yamlpath << " for source " << M
//        .getSourceFileName() << "\n";

        if(getRelativeSourcePath(M.getSourceFileName(), relativePath)) {
            errs() << "Could not get relative path\n";
            throw std::exception();
        }
        relativeSourcePath.append(relativePath.begin(), relativePath.end());

        std::error_code EC;
        raw_fd_ostream ymlout(yamlpath, EC);

        std::vector<std::string> globals;
        std::vector<std::string> functions;

        for (auto *G: definedGlobals) {
            globals.push_back(G->getName().str());
        }

        for (auto *F: definedFunctions) {
            functions.push_back(F->getName().str());
        }

        FileSymbols file;
        file.file = relativeSourcePath;
        file.functions = functions;
        file.globals = globals;

        yaml::Output yout(ymlout);
        yout << file;

        /* Close yml file */
        ymlout.close();
    }
}

