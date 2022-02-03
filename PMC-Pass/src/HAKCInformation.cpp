//
// Created by derrick on 8/20/21.
//

#include "HAKCPass.h"

#include "llvm/Support/FileSystem.h"

LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::YamlSymbol)
LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::YamlFile)
LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::YamlClique)
LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::YamlCompartment)
LLVM_YAML_IS_SEQUENCE_VECTOR(hakc::YamlInformation)


namespace hakc {

    HAKCCompartment::HAKCCompartment(YamlCompartment& compartment, LLVMContext &C) : 
    id(ConstantInt::get(IntegerType::getInt64Ty(C), compartment.id)),
    entry_token(ConstantInt::get(IntegerType::getInt64Ty(C), compartment.entry_token)),
    targets(),
    cliques()
    {}

    void HAKCCompartment::addClique(std::shared_ptr<HAKCClique> clique, std::shared_ptr<HAKCCompartment> compart) {
        cliques.insert(clique);
        clique->setCompartment(compart);
    }

    void HAKCCompartment::addTarget(std::shared_ptr<HAKCCompartment> target) {
        targets.insert(target);
    }

    std::shared_ptr<HAKCClique> HAKCCompartment::getClique(ConstantInt *color) {
        for (auto &clique : cliques) {
            if (clique->getColor() == color) {
                return clique;
            }
        }

        errs() << "Could not find clique ";
        errs() << color->getZExtValue();
        errs() << " in compartment ";
        errs() << id->getZExtValue() << "\n";
        throw std::exception();
    }

    ConstantInt* HAKCCompartment::getID() {
        return id;
    }

    ConstantInt* HAKCCompartment::getEntryToken() {
        return entry_token;
    }

    std::set<std::shared_ptr<HAKCCompartment>> HAKCCompartment::getTargets() {
        return targets;
    }



    HAKCClique::HAKCClique(std::shared_ptr<HAKCCompartment> clique_compartment, ConstantInt* clique_color, ConstantInt* clique_access_token) : 
    compartment(clique_compartment),
    // access_token(clique_access_token),
    symbols()
    {
        color = clique_color;
        access_token = clique_access_token;
        // compartment = clique_compartment;
    }

    void HAKCClique::setCompartment(std::shared_ptr<HAKCCompartment> compart) {
        compartment = compart;
    }

    void HAKCClique::addSymbol(std::shared_ptr<HAKCSymbol> symbol) {
        symbols.insert(symbol);
    }

    ConstantInt *HAKCClique::getAccessToken() {
        return access_token;
    }

    ConstantInt *HAKCClique::getColor() {
        return color;
    }

    ConstantInt *HAKCClique::getCompartmentID() {
        return compartment->getID();
    }

    std::shared_ptr<HAKCCompartment> HAKCClique::getCompartment() {
        return compartment;
    }

    HAKCSymbol::HAKCSymbol(std::string sym_name, std::shared_ptr<HAKCClique> clique, std::shared_ptr<HAKCFile> file) :
    clique(clique), name(sym_name), file(file) {
        file->addCompartment(clique->getCompartment());
    }

    StringRef HAKCSymbol::getName() {
        return name;
    }

    std::shared_ptr<HAKCCompartment> HAKCSymbol::getCompartment() {
        return clique->getCompartment();
    }

    std::shared_ptr<HAKCClique> HAKCSymbol::getClique() {
        return clique;
    }

    ConstantInt* HAKCSymbol::getColor() {
        return clique->getColor();
    }

    ConstantInt* HAKCSymbol::getCompartmentID() {
        return getCompartment()->getID();
    }

    HAKCFile::HAKCFile(YamlFile& file, LLVMContext &C) :
    path(file.name),
    symbols(),
    compartments() 
    {
        guid = ConstantInt::get(IntegerType::getInt64Ty(C), file.guid);

    }

    void HAKCFile::addSymbol(std::shared_ptr<HAKCSymbol> symbol) {
        symbols.insert(symbol);
    }
    
    void HAKCFile::addCompartment(std::shared_ptr<HAKCCompartment> compartment) {
        compartments.insert(compartment);
    }

    ConstantInt *HAKCFile::getColor(StringRef name) {
        for (auto &sym : symbols) {
            if (sym->getName() == name) {
                return sym->getColor();
            }
        }

        return nullptr;
    }

    ConstantInt *HAKCFile::getCompartmentID(StringRef name) {
        for (auto &sym : symbols) {
            if (sym->getName() == name) {
                return sym->getCompartmentID();
            }
        }

        return nullptr;
    }

    ConstantInt *HAKCFile::getAccessToken(StringRef name) {
        for (auto &sym : symbols) {
            if (sym->getName() == name) {
                return sym->getClique()->getAccessToken();
            }
        }

        return nullptr;
    }

    bool HAKCFile::hasCompartments() {
        return !compartments.empty();
    }
   
    HAKCSystemInformation::HAKCSystemInformation(llvm::Module &M) : Module(M) { // TODO
        YamlIn data;

        if(!sys::fs::exists(yaml_file)) {
            errs() << "Could not find YAML file " << yaml_file << "\n";
            throw std::exception();
        }
        ErrorOr<std::unique_ptr<MemoryBuffer>> mb = MemoryBuffer::getFile(yaml_file);
        yaml::Input yin(mb.get()->getMemBufferRef().getBuffer());

        assert(!yin.error() && "Error parsing yaml file");
        yin >> data;

        IntegerType *i64_type = IntegerType::getInt64Ty(M.getContext());
        YamlInformation yi = data[0];

        for (YamlCompartment &comp : yi.compartments) {
            compartments[comp.id] = std::make_shared<HAKCCompartment>(comp, M.getContext());

            for (YamlClique &y_clique : comp.cliques) {
                ConstantInt* color = ConstantInt::get(i64_type, (uint64_t) y_clique.color);
                ConstantInt* access_token = ConstantInt::get(i64_type, y_clique.access_token);
                std::shared_ptr<HAKCClique> clique = std::make_shared<HAKCClique>(compartments[comp.id], color, access_token);
                compartments[comp.id]->addClique(clique, compartments[comp.id]);
            }
        }

        for (YamlCompartment &comp : yi.compartments) {
            for (auto &id : comp.targets) {
                getCompartment(comp.id)->addTarget(getCompartment(id));
            }
        }

        for (YamlFile &file : yi.files) {
            files[file.name] = std::make_shared<HAKCFile>(file, M.getContext());
            for (YamlSymbol &sym : file.symbols) {
                std::shared_ptr<HAKCClique> clique = getClique(sym.compartment, ConstantInt::get(i64_type, (uint64_t) sym.color));
                std::shared_ptr<HAKCSymbol> symbol = std::make_shared<HAKCSymbol>(sym.name, clique, files[file.name]);
                files[file.name]->addSymbol(symbol);
                clique->addSymbol(symbol);
            }
        }
    }

    std::shared_ptr<HAKCCompartment> HAKCSystemInformation::getCompartment(uint64_t id) {
        std::map<uint64_t, std::shared_ptr<HAKCCompartment>>::iterator it;
        it = compartments.find(id);

        if (it != compartments.end()) {
            return it->second;
        } else {
            errs() << "Couldn't find compartment" << id << "\n";
            throw std::exception();
        }
    }

    std::shared_ptr<HAKCClique> HAKCSystemInformation::getClique(uint64_t compartment, ConstantInt *color) {
        std::map<uint64_t, std::shared_ptr<HAKCCompartment>>::iterator it;
        it = compartments.find(compartment);

        if (it != compartments.end()) {
            return it->second->getClique(color);
        } 

        errs() << "Couldn't find compartment" << compartment << "\n";
        throw std::exception();
    }

    ConstantInt *HAKCSystemInformation::getElementColor(StringRef file, StringRef element) {
        auto hakcFile = getFile(file);

        if (hakcFile) {
            return hakcFile->getColor(element);
        }

        return nullptr;
    }

    ConstantInt *HAKCSystemInformation::getElementCompartment(StringRef file, StringRef element) {
        auto hakcFile = getFile(file);

        if (hakcFile) {
            return hakcFile->getCompartmentID(element);
        }

        return nullptr;
    }

    ConstantInt *HAKCSystemInformation::getElementAccessToken(StringRef file, StringRef element) {
        auto hakcFile = getFile(file);

        if (hakcFile) {
            return hakcFile->getAccessToken(element);
        }
        return nullptr;
    }

    ConstantInt *HAKCSystemInformation::getEntryToken(uint64_t compartment) {
        std::map<uint64_t, std::shared_ptr<HAKCCompartment>>::iterator it;
        it = compartments.find(compartment);

        if (it != compartments.end()) {
            return it->second->getEntryToken();
        }

        return nullptr;
    }

    GlobalVariable *HAKCSystemInformation::getTargets(uint64_t compartment) {
        std::map<uint64_t, std::shared_ptr<HAKCCompartment>>::iterator it;
        it = compartments.find(compartment);

        if (it != compartments.end()) {
            std::string name = "entry_tokens_" + std::to_string(compartment);
            GlobalVariable *entry_tokens_arr = Module.getNamedGlobal(name);
            if(entry_tokens_arr) {
                return entry_tokens_arr;
            }

            if(it->second->getTargets().empty()) {
                return nullptr;
            }

            StructType *claque_entry_tok_t = StructType::getTypeByName(Module.getContext(), "claque_entry_token");
            Type *intTy64 = Type::getInt64Ty(Module.getContext());

            if (!claque_entry_tok_t) {
                claque_entry_tok_t = StructType::create({intTy64, intTy64}, "claque_entry_token");
            }

            ArrayType *claque_etoken_array_t = ArrayType::get(claque_entry_tok_t, it->second->getTargets().size());
            std::vector<Constant *> vector_array;

            std::set<std::shared_ptr<HAKCCompartment>> target_set = it->second->getTargets();
            for (auto &t : target_set) {
                ConstantInt *token = t->getEntryToken();
                assert(token && "Could not find entry token");

                Constant *const_entry = ConstantStruct::get(claque_entry_tok_t, {t->getID(), token});
                vector_array.push_back(const_entry);
            }

            Module.getOrInsertGlobal(name, claque_etoken_array_t);
            entry_tokens_arr = Module.getNamedGlobal(name);
            entry_tokens_arr->setConstant(true);
            entry_tokens_arr->setLinkage(GlobalValue::InternalLinkage);
            entry_tokens_arr->setInitializer(llvm::ConstantArray::get(claque_etoken_array_t, ArrayRef<Constant *>(vector_array)));

            return entry_tokens_arr;
            
            
        } else {
            errs() << "Couldn't find compartment" << compartment << "\n";
            throw std::exception();
        }
    }

    std::shared_ptr<HAKCFile> HAKCSystemInformation::getFile(StringRef file) {
        SmallVector<char> relativePath;
        if(getRelativeSourcePath(file, relativePath)) {
            errs() << "Could not get relative path for " << file << "\n";
            throw std::exception();
        }
        std::string fileName(relativePath.begin(), relativePath.end());
        if(files.find(fileName) != files.end()) {
            return files[fileName];
        }

        return std::shared_ptr<HAKCFile>(nullptr);
    }

    bool HAKCSystemInformation::hasFile(StringRef file) {
        bool result = false;

        auto hakcFile = getFile(file);
        if(hakcFile) {
            result = hakcFile->hasCompartments();
        }

        return result;
    }

    llvm::Module& HAKCSystemInformation::getModule() {
        return Module;
    }

    std::string HAKCSystemInformation::getColorFromValue(ConstantInt *color) {
        switch (color->getZExtValue()) {
            case SILVER_CLIQUE:
                return "SILVER_CLIQUE";
            case GREEN_CLIQUE:
                return "GREEN_CLIQUE";
            case RED_CLIQUE:
                return "RED_CLIQUE";
            case ORANGE_CLIQUE:
                return "ORANGE_CLIQUE";
            case YELLOW_CLIQUE:
                return "YELLOW_CLIQUE";
            case PURPLE_CLIQUE:
                return "PURPLE_CLIQUE";
            case BLUE_CLIQUE:
                return "BLUE_CLIQUE";
            case GREY_CLIQUE:
                return "GREY_CLIQUE";
            case PINK_CLIQUE:
                return "PINK_CLIQUE";
            case BROWN_CLIQUE:
                return "BROWN_CLIQUE";
            case WHITE_CLIQUE:
                return "WHITE_CLIQUE";
            case BLACK_CLIQUE:
                return "BLACK_CLIQUE";
            case TEAL_CLIQUE:
                return "TEAL_CLIQUE";
            case VIOLET_CLIQUE:
                return "VIOLET_CLIQUE";
            case CRIMSON_CLIQUE:
                return "CRIMSON_CLIQUE";
            case GOLD_CLIQUE:
                return "GOLD_CLIQUE";
            default:
                errs() << "number " << color->getZExtValue() << "isn't a valid color\n";
                return "INVALID_CLIQUE";
        }
    }
}// namespace hakc

template<>
struct yaml::ScalarEnumerationTraits<hakc::func_color_t> {
    static void enumeration(yaml::IO &io, hakc::func_color_t &value) {
        io.enumCase(value, "SILVER_CLIQUE", hakc::SILVER_CLIQUE);
        io.enumCase(value, "GREEN_CLIQUE", hakc::GREEN_CLIQUE);
        io.enumCase(value, "RED_CLIQUE", hakc::RED_CLIQUE);
        io.enumCase(value, "ORANGE_CLIQUE", hakc::ORANGE_CLIQUE);
        io.enumCase(value, "YELLOW_CLIQUE", hakc::YELLOW_CLIQUE);
        io.enumCase(value, "PURPLE_CLIQUE", hakc::PURPLE_CLIQUE);
        io.enumCase(value, "BLUE_CLIQUE", hakc::BLUE_CLIQUE);
        io.enumCase(value, "GREY_CLIQUE", hakc::GREY_CLIQUE);
        io.enumCase(value, "PINK_CLIQUE", hakc::PINK_CLIQUE);
        io.enumCase(value, "BROWN_CLIQUE", hakc::BROWN_CLIQUE);
        io.enumCase(value, "WHITE_CLIQUE", hakc::WHITE_CLIQUE);
        io.enumCase(value, "BLACK_CLIQUE", hakc::BLACK_CLIQUE);
        io.enumCase(value, "TEAL_CLIQUE", hakc::TEAL_CLIQUE);
        io.enumCase(value, "VIOLET_CLIQUE", hakc::VIOLET_CLIQUE);
        io.enumCase(value, "CRIMSON_CLIQUE", hakc::CRIMSON_CLIQUE);
        io.enumCase(value, "GOLD_CLIQUE", hakc::GOLD_CLIQUE);
        io.enumCase(value, "NO_CLIQUE", hakc::NO_CLIQUE);
    }
};

template<>
struct yaml::MappingTraits<hakc::YamlSymbol> {
    static void mapping(yaml::IO &io, hakc::YamlSymbol &info) {
        io.mapRequired("CLIQUE", info.color);
        io.mapRequired("NAME", info.name);
        io.mapRequired("COMPARTMENT", info.compartment);
    }
};

template<>
struct yaml::MappingTraits<hakc::YamlFile> {
    static void mapping(yaml::IO &io, hakc::YamlFile &info) {
        io.mapRequired("GUID", info.guid);
        io.mapRequired("PATH", info.name);
        io.mapRequired("SYMBOLS", info.symbols);
    }
};

template<>
struct yaml::MappingTraits<hakc::YamlClique> {
    static void mapping(yaml::IO &io, hakc::YamlClique &info) {
        io.mapRequired("COLOR", info.color);
        io.mapRequired("ACCESS_TOKEN", info.access_token);
    }
};

template<>
struct yaml::MappingTraits<hakc::YamlCompartment> {
    static void mapping(yaml::IO &io, hakc::YamlCompartment &info) {
        io.mapRequired("ID", info.id);
        io.mapRequired("TARGETS", info.targets);
        io.mapRequired("CLIQUES", info.cliques);
        io.mapRequired("ENTRY_TOKEN", info.entry_token);
    }
};

template<>
struct yaml::MappingTraits<hakc::YamlInformation> {
    static void mapping(yaml::IO &io, hakc::YamlInformation &info) {
        io.mapRequired("COMPARTMENTS", info.compartments);
        io.mapRequired("FILES", info.files);
    }
};