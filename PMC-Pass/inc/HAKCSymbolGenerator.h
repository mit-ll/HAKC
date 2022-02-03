//
// Created by derrick on 9/9/21.
//

#ifndef PMC_HAKCSYMBOLGENERATOR_H
#define PMC_HAKCSYMBOLGENERATOR_H

#include "llvm/IR/Module.h"

#include <set>

using namespace llvm;

namespace hakc {
    class HAKCSymbolGenerator {
    public:
        HAKCSymbolGenerator(Module &M);

    protected:
        void gatherFunctions();
        void gatherGlobals();
        void output();

    protected:
        Module &M;
        std::set<Function*> definedFunctions;
        std::set<GlobalVariable*> definedGlobals;
    };

    struct FileSymbols {
        std::string                 file;
        std::vector<std::string>    functions;
        std::vector<std::string>    globals;
    };
}


#endif//PMC_HAKCSYMBOLGENERATOR_H
