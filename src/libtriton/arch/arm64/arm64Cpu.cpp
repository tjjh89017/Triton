//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <cstring>

#include <api.hpp>
#include <architecture.hpp>
#include <callbacks.hpp>
#include <coreUtils.hpp>
#include <cpuSize.hpp>
#include <exceptions.hpp>
#include <externalLibs.hpp>
#include <immediate.hpp>
#include <arm64Cpu.hpp>
#include <arm64Specifications.hpp>

#ifdef TRITON_PYTHON_BINDINGS
  #include <pythonBindings.hpp>
#endif



namespace triton {
  namespace arch {
    namespace arm64 {

      arm64Cpu::arm64Cpu() {
        this->clear();
      }


      arm64Cpu::arm64Cpu(const arm64Cpu& other) {
        this->copy(other);
      }


      arm64Cpu::~arm64Cpu() {
        this->memory.clear();
      }


      void arm64Cpu::copy(const arm64Cpu& other) {
        this->memory = other.memory;
        memcpy(this->x0,       other.x0,     sizeof(this->x1));
        memcpy(this->x1,       other.x1,     sizeof(this->x1));
        memcpy(this->x2,       other.x2,     sizeof(this->x2));
        memcpy(this->x3,       other.x3,     sizeof(this->x3));
        memcpy(this->x4,       other.x4,     sizeof(this->x4));
        memcpy(this->x5,       other.x5,     sizeof(this->x5));
        memcpy(this->x6,       other.x6,     sizeof(this->x6));
        memcpy(this->x7,       other.x7,     sizeof(this->x7));
        memcpy(this->x8,       other.x8,     sizeof(this->x8));
        memcpy(this->x9,       other.x9,     sizeof(this->x9));
        memcpy(this->x10,      other.x10,    sizeof(this->x10));
        memcpy(this->x11,      other.x11,    sizeof(this->x11));
        memcpy(this->x12,      other.x12,    sizeof(this->x12));
        memcpy(this->x13,      other.x13,    sizeof(this->x13));
        memcpy(this->x14,      other.x14,    sizeof(this->x14));
        memcpy(this->x15,      other.x15,    sizeof(this->x15));
        memcpy(this->x16,      other.x16,    sizeof(this->x16));
        memcpy(this->x17,      other.x17,    sizeof(this->x17));
        memcpy(this->x18,      other.x18,    sizeof(this->x18));
        memcpy(this->x19,      other.x19,    sizeof(this->x19));
        memcpy(this->x20,      other.x20,    sizeof(this->x20));
        memcpy(this->x21,      other.x21,    sizeof(this->x21));
        memcpy(this->x22,      other.x22,    sizeof(this->x22));
        memcpy(this->x23,      other.x23,    sizeof(this->x23));
        memcpy(this->x24,      other.x24,    sizeof(this->x24));
        memcpy(this->x25,      other.x25,    sizeof(this->x25));
        memcpy(this->x26,      other.x26,    sizeof(this->x26));
        memcpy(this->x27,      other.x27,    sizeof(this->x27));
        memcpy(this->x28,      other.x28,    sizeof(this->x28));
        memcpy(this->x29,      other.x29,    sizeof(this->x29));
        memcpy(this->x30,      other.x30,    sizeof(this->x30));
      }


      void arm64Cpu::init(void) {
        /* Define registers ========================================================= */
        triton::arch::arm64::arm64_reg_rax    = triton::arch::Register(triton::arch::arm64::ID_REG_RAX);

        /* Update python env ======================================================== */
        #ifdef TRITON_PYTHON_BINDINGS
          triton::bindings::python::initRegNamespace();
          triton::bindings::python::initCpuSizeNamespace();
          triton::bindings::python::initARM64OpcodesNamespace();
          triton::bindings::python::initARM64PrefixesNamespace();
          #if defined(__unix__) || defined(__APPLE__)
            triton::bindings::python::initSyscallNamespace();
          #endif
        #endif
      }


      void arm64Cpu::clear(void) {
        /* Clear memory */
        this->memory.clear();

        /* Clear registers */
        memset(this->x0,       0,     sizeof(this->x1));
        memset(this->x1,       0,     sizeof(this->x1));
        memset(this->x2,       0,     sizeof(this->x2));
        memset(this->x3,       0,     sizeof(this->x3));
        memset(this->x4,       0,     sizeof(this->x4));
        memset(this->x5,       0,     sizeof(this->x5));
        memset(this->x6,       0,     sizeof(this->x6));
        memset(this->x7,       0,     sizeof(this->x7));
        memset(this->x8,       0,     sizeof(this->x8));
        memset(this->x9,       0,     sizeof(this->x9));
        memset(this->x10,      0,    sizeof(this->x10));
        memset(this->x11,      0,    sizeof(this->x11));
        memset(this->x12,      0,    sizeof(this->x12));
        memset(this->x13,      0,    sizeof(this->x13));
        memset(this->x14,      0,    sizeof(this->x14));
        memset(this->x15,      0,    sizeof(this->x15));
        memset(this->x16,      0,    sizeof(this->x16));
        memset(this->x17,      0,    sizeof(this->x17));
        memset(this->x18,      0,    sizeof(this->x18));
        memset(this->x19,      0,    sizeof(this->x19));
        memset(this->x20,      0,    sizeof(this->x20));
        memset(this->x21,      0,    sizeof(this->x21));
        memset(this->x22,      0,    sizeof(this->x22));
        memset(this->x23,      0,    sizeof(this->x23));
        memset(this->x24,      0,    sizeof(this->x24));
        memset(this->x25,      0,    sizeof(this->x25));
        memset(this->x26,      0,    sizeof(this->x26));
        memset(this->x27,      0,    sizeof(this->x27));
        memset(this->x28,      0,    sizeof(this->x28));
        memset(this->x29,      0,    sizeof(this->x29));
        memset(this->x30,      0,    sizeof(this->x30));
      }


      void arm64Cpu::operator=(const arm64Cpu& other) {
        this->copy(other);
      }


      bool arm64Cpu::isFlag(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_AF && regId <= triton::arch::arm64::ID_REG_FZ) ? true : false);
      }


      bool arm64Cpu::isRegister(triton::uint32 regId) const {
        return (this->isGPR(regId) || this->isMMX(regId) || this->isSSE(regId) || this->isAVX256(regId) || this->isAVX512(regId) || this->isControl(regId) || this->isSegment(regId));
      }


      bool arm64Cpu::isRegisterValid(triton::uint32 regId) const {
        return (this->isFlag(regId) || this->isRegister(regId));
      }


      bool arm64Cpu::isGPR(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_RAX && regId <= triton::arch::arm64::ID_REG_EFLAGS) ? true : false);
      }


      bool arm64Cpu::isMMX(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_MM0 && regId <= triton::arch::arm64::ID_REG_MM7) ? true : false);
      }


      bool arm64Cpu::isSSE(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_MXCSR && regId <= triton::arch::arm64::ID_REG_XMM15) ? true : false);
      }


      bool arm64Cpu::isAVX256(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_YMM0 && regId <= triton::arch::arm64::ID_REG_YMM15) ? true : false);
      }


      bool arm64Cpu::isAVX512(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_ZMM0 && regId <= triton::arch::arm64::ID_REG_ZMM31) ? true : false);
      }


      bool arm64Cpu::isControl(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_CR0 && regId <= triton::arch::arm64::ID_REG_CR15) ? true : false);
      }


      bool arm64Cpu::isSegment(triton::uint32 regId) const {
        return ((regId >= triton::arch::arm64::ID_REG_CS && regId <= triton::arch::arm64::ID_REG_SS) ? true : false);
      }


      triton::uint32 arm64Cpu::invalidRegister(void) const {
        return triton::arch::arm64::ID_REG_INVALID;
      }


      triton::uint32 arm64Cpu::numberOfRegisters(void) const {
        return triton::arch::arm64::ID_REG_LAST_ITEM;
      }


      triton::uint32 arm64Cpu::registerSize(void) const {
        return QWORD_SIZE;
      }


      triton::uint32 arm64Cpu::registerBitSize(void) const {
        return QWORD_SIZE_BIT;
      }


      std::tuple<std::string, triton::uint32, triton::uint32, triton::uint32> arm64Cpu::getRegisterInformation(triton::uint32 reg) const {
        return triton::arch::arm64::registerIdToRegisterInformation(reg);
      }


      std::set<triton::arch::Register*> arm64Cpu::getAllRegisters(void) const {
        std::set<triton::arch::Register*> ret;

        for (triton::uint32 index = 0; index < triton::arch::arm64::ID_REG_LAST_ITEM; index++) {
          if (this->isRegisterValid(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);
        }

        return ret;
      }


      std::set<triton::arch::Register*> arm64Cpu::getParentRegisters(void) const {
        std::set<triton::arch::Register*> ret;

        for (triton::uint32 index = 0; index < triton::arch::arm64::ID_REG_LAST_ITEM; index++) {
          /* Add GPR */
          if (triton::arch::arm64::arm64_regs[index]->getSize() == this->registerSize())
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add Flags */
          else if (this->isFlag(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add MMX */
          else if (this->isMMX(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add SSE */
          else if (this->isSSE(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add AVX-256 */
          else if (this->isAVX256(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add AVX-512 */
          else if (this->isAVX512(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);

          /* Add Control */
          else if (this->isControl(triton::arch::arm64::arm64_regs[index]->getId()))
            ret.insert(triton::arch::arm64::arm64_regs[index]);
        }

        return ret;
      }


      void arm64Cpu::disassembly(triton::arch::Instruction& inst) const {
        triton::extlibs::capstone::csh       handle;
        triton::extlibs::capstone::cs_insn*  insn;
        triton::usize                        count = 0;

        /* Check if the opcodes and opcodes' size are defined */
        if (inst.getOpcodes() == nullptr || inst.getSize() == 0)
          throw triton::exceptions::Disassembly("arm64Cpu::disassembly(): Opcodes and opcodesSize must be definied.");

        /* Open capstone */
        if (triton::extlibs::capstone::cs_open(triton::extlibs::capstone::CS_ARCH_ARM64, triton::extlibs::capstone::CS_MODE_64, &handle) != triton::extlibs::capstone::CS_ERR_OK)
          throw triton::exceptions::Disassembly("arm64Cpu::disassembly(): Cannot open capstone.");

        /* Init capstone's options */
        triton::extlibs::capstone::cs_option(handle, triton::extlibs::capstone::CS_OPT_DETAIL, triton::extlibs::capstone::CS_OPT_ON);
        triton::extlibs::capstone::cs_option(handle, triton::extlibs::capstone::CS_OPT_SYNTAX, triton::extlibs::capstone::CS_OPT_SYNTAX_INTEL);

        /* Let's disass and build our operands */
        count = triton::extlibs::capstone::cs_disasm(handle, inst.getOpcodes(), inst.getSize(), inst.getAddress(), 0, &insn);
        if (count > 0) {
          triton::extlibs::capstone::cs_detail* detail = insn->detail;
          for (triton::uint32 j = 0; j < 1; j++) {

            /* Init the disassembly */
            std::stringstream str;
            str << insn[j].mnemonic << " " <<  insn[j].op_str;
            inst.setDisassembly(str.str());

            /* Refine the size */
            inst.setSize(insn[j].size);

            /* Init the instruction's type */
            inst.setType(triton::arch::arm64::capstoneInstructionToTritonInstruction(insn[j].id));

            /* Init the instruction's prefix */
            inst.setPrefix(triton::arch::arm64::capstonePrefixToTritonPrefix(detail->arm64.prefix[0]));

            /* Init operands */
            for (triton::uint32 n = 0; n < detail->arm64.op_count; n++) {
              triton::extlibs::capstone::cs_arm64_op* op = &(detail->arm64.operands[n]);
              switch(op->type) {

                case triton::extlibs::capstone::ARM64_OP_IMM:
                  inst.operands.push_back(triton::arch::OperandWrapper(triton::arch::Immediate(op->imm, op->size)));
                  break;

                case triton::extlibs::capstone::ARM64_OP_MEM: {
                  triton::arch::MemoryAccess mem = inst.popMemoryAccess();

                  /* Set the size if the memory is not valid */
                  if (!mem.isValid())
                    mem.setPair(std::make_pair(((op->size * BYTE_SIZE_BIT) - 1), 0));

                  /* LEA if exists */
                  triton::arch::Register segment(triton::arch::arm64::capstoneRegisterToTritonRegister(op->mem.segment));
                  triton::arch::Register base(triton::arch::arm64::capstoneRegisterToTritonRegister(op->mem.base));
                  triton::arch::Register index(triton::arch::arm64::capstoneRegisterToTritonRegister(op->mem.index));
                  triton::arch::Immediate disp(op->mem.disp, base.isValid() ? base.getSize() : index.isValid() ? index.getSize() : op->size);
                  triton::arch::Immediate scale(op->mem.scale, base.isValid() ? base.getSize() : index.isValid() ? index.getSize() : op->size);

                  /* Specify that LEA contains a PC relative */
                  if (base.getId() == TRITON_ARM64_REG_PC.getId())
                    mem.setPcRelative(inst.getNextAddress());

                  mem.setSegmentRegister(segment);
                  mem.setBaseRegister(base);
                  mem.setIndexRegister(index);
                  mem.setDisplacement(disp);
                  mem.setScale(scale);

                  inst.operands.push_back(triton::arch::OperandWrapper(mem));
                  break;
                }

                case triton::extlibs::capstone::ARM64_OP_REG:
                  inst.operands.push_back(triton::arch::OperandWrapper(inst.getRegisterState(triton::arch::arm64::capstoneRegisterToTritonRegister(op->reg))));
                  break;

                default:
                  throw triton::exceptions::Disassembly("arm64Cpu::disassembly(): Invalid operand.");
              }
            }

          }
          /* Set branch */
          if (detail->groups_count > 0) {
            for (triton::uint32 n = 0; n < detail->groups_count; n++) {
              if (detail->groups[n] == triton::extlibs::capstone::ARM64_GRP_JUMP)
                inst.setBranch(true);
              if (detail->groups[n] == triton::extlibs::capstone::ARM64_GRP_JUMP ||
                  detail->groups[n] == triton::extlibs::capstone::ARM64_GRP_CALL ||
                  detail->groups[n] == triton::extlibs::capstone::ARM64_GRP_RET)
                inst.setControlFlow(true);
            }
          }
          /* Free capstone stuffs */
          triton::extlibs::capstone::cs_free(insn, count);
        }
        else
          throw triton::exceptions::Disassembly("arm64Cpu::disassembly(): Failed to disassemble the given code.");

        triton::extlibs::capstone::cs_close(&handle);
        return;
      }


      void arm64Cpu::buildSemantics(triton::arch::Instruction& inst) const {
        if (!inst.getType())
          throw triton::exceptions::Cpu("arm64Cpu::buildSemantics(): You must disassemble the instruction before.");
        triton::arch::arm64::semantics::build(inst);
      }


      triton::uint8 arm64Cpu::getConcreteMemoryValue(triton::uint64 addr) const {
        triton::api.processCallbacks(triton::callbacks::MEMORY_HIT, addr);

        if (this->memory.find(addr) == this->memory.end())
          return 0x00;

        return this->memory.at(addr);
      }


      triton::uint512 arm64Cpu::getConcreteMemoryValue(const triton::arch::MemoryAccess& mem) const {
        triton::uint512 ret = 0;
        triton::uint64 addr = mem.getAddress();
        triton::uint32 size = mem.getSize();

        if (size == 0 || size > DQQWORD_SIZE)
          throw triton::exceptions::Cpu("arm64Cpu::getConcreteMemoryValue(): Invalid size memory.");

        for (triton::sint32 i = size-1; i >= 0; i--)
          ret = ((ret << BYTE_SIZE_BIT) | this->getConcreteMemoryValue(addr+i));

        return ret;
      }


      std::vector<triton::uint8> arm64Cpu::getConcreteMemoryAreaValue(triton::uint64 baseAddr, triton::usize size) const {
        std::vector<triton::uint8> area;

        for (triton::usize index = 0; index < size; index++)
          area.push_back(this->getConcreteMemoryValue(baseAddr+index));

        return area;
      }


      triton::uint512 arm64Cpu::getConcreteRegisterValue(const triton::arch::Register& reg) const {
        triton::uint512 value = 0;
        switch (reg.getId()) {
          case triton::arch::arm64::ID_REG_RAX: return (*((triton::uint64*)(this->rax)));
          case triton::arch::arm64::ID_REG_EAX: return (*((triton::uint32*)(this->rax)));
          case triton::arch::arm64::ID_REG_AX:  return (*((triton::uint16*)(this->rax)));
          case triton::arch::arm64::ID_REG_AH:  return (*((triton::uint8*)(this->rax+1)));
          case triton::arch::arm64::ID_REG_AL:  return (*((triton::uint8*)(this->rax)));

          case triton::arch::arm64::ID_REG_RBX: return (*((triton::uint64*)(this->rbx)));
          case triton::arch::arm64::ID_REG_EBX: return (*((triton::uint32*)(this->rbx)));
          case triton::arch::arm64::ID_REG_BX:  return (*((triton::uint16*)(this->rbx)));
          case triton::arch::arm64::ID_REG_BH:  return (*((triton::uint8*)(this->rbx+1)));
          case triton::arch::arm64::ID_REG_BL:  return (*((triton::uint8*)(this->rbx)));

          case triton::arch::arm64::ID_REG_RCX: return (*((triton::uint64*)(this->rcx)));
          case triton::arch::arm64::ID_REG_ECX: return (*((triton::uint32*)(this->rcx)));
          case triton::arch::arm64::ID_REG_CX:  return (*((triton::uint16*)(this->rcx)));
          case triton::arch::arm64::ID_REG_CH:  return (*((triton::uint8*)(this->rcx+1)));
          case triton::arch::arm64::ID_REG_CL:  return (*((triton::uint8*)(this->rcx)));

          case triton::arch::arm64::ID_REG_RDX: return (*((triton::uint64*)(this->rdx)));
          case triton::arch::arm64::ID_REG_EDX: return (*((triton::uint32*)(this->rdx)));
          case triton::arch::arm64::ID_REG_DX:  return (*((triton::uint16*)(this->rdx)));
          case triton::arch::arm64::ID_REG_DH:  return (*((triton::uint8*)(this->rdx+1)));
          case triton::arch::arm64::ID_REG_DL:  return (*((triton::uint8*)(this->rdx)));

          case triton::arch::arm64::ID_REG_RDI: return (*((triton::uint64*)(this->rdi)));
          case triton::arch::arm64::ID_REG_EDI: return (*((triton::uint32*)(this->rdi)));
          case triton::arch::arm64::ID_REG_DI:  return (*((triton::uint16*)(this->rdi)));
          case triton::arch::arm64::ID_REG_DIL: return (*((triton::uint8*)(this->rdi)));

          case triton::arch::arm64::ID_REG_RSI: return (*((triton::uint64*)(this->rsi)));
          case triton::arch::arm64::ID_REG_ESI: return (*((triton::uint32*)(this->rsi)));
          case triton::arch::arm64::ID_REG_SI:  return (*((triton::uint16*)(this->rsi)));
          case triton::arch::arm64::ID_REG_SIL: return (*((triton::uint8*)(this->rsi)));

          case triton::arch::arm64::ID_REG_RSP: return (*((triton::uint64*)(this->rsp)));
          case triton::arch::arm64::ID_REG_ESP: return (*((triton::uint32*)(this->rsp)));
          case triton::arch::arm64::ID_REG_SP:  return (*((triton::uint16*)(this->rsp)));
          case triton::arch::arm64::ID_REG_SPL: return (*((triton::uint8*)(this->rsp)));

          case triton::arch::arm64::ID_REG_RBP: return (*((triton::uint64*)(this->rbp)));
          case triton::arch::arm64::ID_REG_EBP: return (*((triton::uint32*)(this->rbp)));
          case triton::arch::arm64::ID_REG_BP:  return (*((triton::uint16*)(this->rbp)));
          case triton::arch::arm64::ID_REG_BPL: return (*((triton::uint8*)(this->rbp)));

          case triton::arch::arm64::ID_REG_RIP: return (*((triton::uint64*)(this->rip)));
          case triton::arch::arm64::ID_REG_EIP: return (*((triton::uint32*)(this->rip)));
          case triton::arch::arm64::ID_REG_IP:  return (*((triton::uint16*)(this->rip)));

          case triton::arch::arm64::ID_REG_EFLAGS: return (*((triton::uint64*)(this->eflags)));

          case triton::arch::arm64::ID_REG_R8:  return (*((triton::uint64*)(this->r8)));
          case triton::arch::arm64::ID_REG_R8D: return (*((triton::uint32*)(this->r8)));
          case triton::arch::arm64::ID_REG_R8W: return (*((triton::uint16*)(this->r8)));
          case triton::arch::arm64::ID_REG_R8B: return (*((triton::uint8*)(this->r8)));

          case triton::arch::arm64::ID_REG_R9:  return (*((triton::uint64*)(this->r9)));
          case triton::arch::arm64::ID_REG_R9D: return (*((triton::uint32*)(this->r9)));
          case triton::arch::arm64::ID_REG_R9W: return (*((triton::uint16*)(this->r9)));
          case triton::arch::arm64::ID_REG_R9B: return (*((triton::uint8*)(this->r9)));

          case triton::arch::arm64::ID_REG_R10:  return (*((triton::uint64*)(this->r10)));
          case triton::arch::arm64::ID_REG_R10D: return (*((triton::uint32*)(this->r10)));
          case triton::arch::arm64::ID_REG_R10W: return (*((triton::uint16*)(this->r10)));
          case triton::arch::arm64::ID_REG_R10B: return (*((triton::uint8*)(this->r10)));

          case triton::arch::arm64::ID_REG_R11:  return (*((triton::uint64*)(this->r11)));
          case triton::arch::arm64::ID_REG_R11D: return (*((triton::uint32*)(this->r11)));
          case triton::arch::arm64::ID_REG_R11W: return (*((triton::uint16*)(this->r11)));
          case triton::arch::arm64::ID_REG_R11B: return (*((triton::uint8*)(this->r11)));

          case triton::arch::arm64::ID_REG_R12:  return (*((triton::uint64*)(this->r12)));
          case triton::arch::arm64::ID_REG_R12D: return (*((triton::uint32*)(this->r12)));
          case triton::arch::arm64::ID_REG_R12W: return (*((triton::uint16*)(this->r12)));
          case triton::arch::arm64::ID_REG_R12B: return (*((triton::uint8*)(this->r12)));

          case triton::arch::arm64::ID_REG_R13:  return (*((triton::uint64*)(this->r13)));
          case triton::arch::arm64::ID_REG_R13D: return (*((triton::uint32*)(this->r13)));
          case triton::arch::arm64::ID_REG_R13W: return (*((triton::uint16*)(this->r13)));
          case triton::arch::arm64::ID_REG_R13B: return (*((triton::uint8*)(this->r13)));

          case triton::arch::arm64::ID_REG_R14:  return (*((triton::uint64*)(this->r14)));
          case triton::arch::arm64::ID_REG_R14D: return (*((triton::uint32*)(this->r14)));
          case triton::arch::arm64::ID_REG_R14W: return (*((triton::uint16*)(this->r14)));
          case triton::arch::arm64::ID_REG_R14B: return (*((triton::uint8*)(this->r14)));

          case triton::arch::arm64::ID_REG_R15:  return (*((triton::uint64*)(this->r15)));
          case triton::arch::arm64::ID_REG_R15D: return (*((triton::uint32*)(this->r15)));
          case triton::arch::arm64::ID_REG_R15W: return (*((triton::uint16*)(this->r15)));
          case triton::arch::arm64::ID_REG_R15B: return (*((triton::uint8*)(this->r15)));

          case triton::arch::arm64::ID_REG_MM0:  return (*((triton::uint64*)(this->mm0)));
          case triton::arch::arm64::ID_REG_MM1:  return (*((triton::uint64*)(this->mm1)));
          case triton::arch::arm64::ID_REG_MM2:  return (*((triton::uint64*)(this->mm2)));
          case triton::arch::arm64::ID_REG_MM3:  return (*((triton::uint64*)(this->mm3)));
          case triton::arch::arm64::ID_REG_MM4:  return (*((triton::uint64*)(this->mm4)));
          case triton::arch::arm64::ID_REG_MM5:  return (*((triton::uint64*)(this->mm5)));
          case triton::arch::arm64::ID_REG_MM6:  return (*((triton::uint64*)(this->mm6)));
          case triton::arch::arm64::ID_REG_MM7:  return (*((triton::uint64*)(this->mm7)));

          case triton::arch::arm64::ID_REG_XMM0:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm0);  return value;
          case triton::arch::arm64::ID_REG_XMM1:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm1);  return value;
          case triton::arch::arm64::ID_REG_XMM2:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm2);  return value;
          case triton::arch::arm64::ID_REG_XMM3:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm3);  return value;
          case triton::arch::arm64::ID_REG_XMM4:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm4);  return value;
          case triton::arch::arm64::ID_REG_XMM5:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm5);  return value;
          case triton::arch::arm64::ID_REG_XMM6:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm6);  return value;
          case triton::arch::arm64::ID_REG_XMM7:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm7);  return value;
          case triton::arch::arm64::ID_REG_XMM8:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm8);  return value;
          case triton::arch::arm64::ID_REG_XMM9:  value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm9);  return value;
          case triton::arch::arm64::ID_REG_XMM10: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm10); return value;
          case triton::arch::arm64::ID_REG_XMM11: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm11); return value;
          case triton::arch::arm64::ID_REG_XMM12: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm12); return value;
          case triton::arch::arm64::ID_REG_XMM13: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm13); return value;
          case triton::arch::arm64::ID_REG_XMM14: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm14); return value;
          case triton::arch::arm64::ID_REG_XMM15: value = triton::utils::fromBufferToUint<triton::uint128>(this->xmm15); return value;

          case triton::arch::arm64::ID_REG_YMM0:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm0);  return value;
          case triton::arch::arm64::ID_REG_YMM1:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm1);  return value;
          case triton::arch::arm64::ID_REG_YMM2:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm2);  return value;
          case triton::arch::arm64::ID_REG_YMM3:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm3);  return value;
          case triton::arch::arm64::ID_REG_YMM4:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm4);  return value;
          case triton::arch::arm64::ID_REG_YMM5:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm5);  return value;
          case triton::arch::arm64::ID_REG_YMM6:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm6);  return value;
          case triton::arch::arm64::ID_REG_YMM7:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm7);  return value;
          case triton::arch::arm64::ID_REG_YMM8:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm8);  return value;
          case triton::arch::arm64::ID_REG_YMM9:  value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm9);  return value;
          case triton::arch::arm64::ID_REG_YMM10: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm10); return value;
          case triton::arch::arm64::ID_REG_YMM11: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm11); return value;
          case triton::arch::arm64::ID_REG_YMM12: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm12); return value;
          case triton::arch::arm64::ID_REG_YMM13: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm13); return value;
          case triton::arch::arm64::ID_REG_YMM14: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm14); return value;
          case triton::arch::arm64::ID_REG_YMM15: value = triton::utils::fromBufferToUint<triton::uint256>(this->ymm15); return value;

          case triton::arch::arm64::ID_REG_ZMM0:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm0);  return value;
          case triton::arch::arm64::ID_REG_ZMM1:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm1);  return value;
          case triton::arch::arm64::ID_REG_ZMM2:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm2);  return value;
          case triton::arch::arm64::ID_REG_ZMM3:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm3);  return value;
          case triton::arch::arm64::ID_REG_ZMM4:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm4);  return value;
          case triton::arch::arm64::ID_REG_ZMM5:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm5);  return value;
          case triton::arch::arm64::ID_REG_ZMM6:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm6);  return value;
          case triton::arch::arm64::ID_REG_ZMM7:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm7);  return value;
          case triton::arch::arm64::ID_REG_ZMM8:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm8);  return value;
          case triton::arch::arm64::ID_REG_ZMM9:  value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm9);  return value;
          case triton::arch::arm64::ID_REG_ZMM10: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm10); return value;
          case triton::arch::arm64::ID_REG_ZMM11: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm11); return value;
          case triton::arch::arm64::ID_REG_ZMM12: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm12); return value;
          case triton::arch::arm64::ID_REG_ZMM13: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm13); return value;
          case triton::arch::arm64::ID_REG_ZMM14: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm14); return value;
          case triton::arch::arm64::ID_REG_ZMM15: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm15); return value;
          case triton::arch::arm64::ID_REG_ZMM16: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm16); return value;
          case triton::arch::arm64::ID_REG_ZMM17: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm17); return value;
          case triton::arch::arm64::ID_REG_ZMM18: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm18); return value;
          case triton::arch::arm64::ID_REG_ZMM19: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm19); return value;
          case triton::arch::arm64::ID_REG_ZMM20: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm20); return value;
          case triton::arch::arm64::ID_REG_ZMM21: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm21); return value;
          case triton::arch::arm64::ID_REG_ZMM22: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm22); return value;
          case triton::arch::arm64::ID_REG_ZMM23: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm23); return value;
          case triton::arch::arm64::ID_REG_ZMM24: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm24); return value;
          case triton::arch::arm64::ID_REG_ZMM25: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm25); return value;
          case triton::arch::arm64::ID_REG_ZMM26: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm26); return value;
          case triton::arch::arm64::ID_REG_ZMM27: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm27); return value;
          case triton::arch::arm64::ID_REG_ZMM28: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm28); return value;
          case triton::arch::arm64::ID_REG_ZMM29: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm29); return value;
          case triton::arch::arm64::ID_REG_ZMM30: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm30); return value;
          case triton::arch::arm64::ID_REG_ZMM31: value = triton::utils::fromBufferToUint<triton::uint512>(this->zmm31); return value;

          case triton::arch::arm64::ID_REG_MXCSR: return (*((triton::uint64*)(this->mxcsr)));

          case triton::arch::arm64::ID_REG_CR0:  return (*((triton::uint64*)(this->cr0)));
          case triton::arch::arm64::ID_REG_CR1:  return (*((triton::uint64*)(this->cr1)));
          case triton::arch::arm64::ID_REG_CR2:  return (*((triton::uint64*)(this->cr2)));
          case triton::arch::arm64::ID_REG_CR3:  return (*((triton::uint64*)(this->cr3)));
          case triton::arch::arm64::ID_REG_CR4:  return (*((triton::uint64*)(this->cr4)));
          case triton::arch::arm64::ID_REG_CR5:  return (*((triton::uint64*)(this->cr5)));
          case triton::arch::arm64::ID_REG_CR6:  return (*((triton::uint64*)(this->cr6)));
          case triton::arch::arm64::ID_REG_CR7:  return (*((triton::uint64*)(this->cr7)));
          case triton::arch::arm64::ID_REG_CR8:  return (*((triton::uint64*)(this->cr8)));
          case triton::arch::arm64::ID_REG_CR9:  return (*((triton::uint64*)(this->cr9)));
          case triton::arch::arm64::ID_REG_CR10: return (*((triton::uint64*)(this->cr10)));
          case triton::arch::arm64::ID_REG_CR11: return (*((triton::uint64*)(this->cr11)));
          case triton::arch::arm64::ID_REG_CR12: return (*((triton::uint64*)(this->cr12)));
          case triton::arch::arm64::ID_REG_CR13: return (*((triton::uint64*)(this->cr13)));
          case triton::arch::arm64::ID_REG_CR14: return (*((triton::uint64*)(this->cr14)));
          case triton::arch::arm64::ID_REG_CR15: return (*((triton::uint64*)(this->cr15)));

          case triton::arch::arm64::ID_REG_IE:  return (((*((triton::uint64*)(this->mxcsr))) >> 0) & 1);
          case triton::arch::arm64::ID_REG_DE:  return (((*((triton::uint64*)(this->mxcsr))) >> 1) & 1);
          case triton::arch::arm64::ID_REG_ZE:  return (((*((triton::uint64*)(this->mxcsr))) >> 2) & 1);
          case triton::arch::arm64::ID_REG_OE:  return (((*((triton::uint64*)(this->mxcsr))) >> 3) & 1);
          case triton::arch::arm64::ID_REG_UE:  return (((*((triton::uint64*)(this->mxcsr))) >> 4) & 1);
          case triton::arch::arm64::ID_REG_PE:  return (((*((triton::uint64*)(this->mxcsr))) >> 5) & 1);
          case triton::arch::arm64::ID_REG_DAZ: return (((*((triton::uint64*)(this->mxcsr))) >> 6) & 1);
          case triton::arch::arm64::ID_REG_IM:  return (((*((triton::uint64*)(this->mxcsr))) >> 7) & 1);
          case triton::arch::arm64::ID_REG_DM:  return (((*((triton::uint64*)(this->mxcsr))) >> 8) & 1);
          case triton::arch::arm64::ID_REG_ZM:  return (((*((triton::uint64*)(this->mxcsr))) >> 9) & 1);
          case triton::arch::arm64::ID_REG_OM:  return (((*((triton::uint64*)(this->mxcsr))) >> 10) & 1);
          case triton::arch::arm64::ID_REG_UM:  return (((*((triton::uint64*)(this->mxcsr))) >> 11) & 1);
          case triton::arch::arm64::ID_REG_PM:  return (((*((triton::uint64*)(this->mxcsr))) >> 12) & 1);
          case triton::arch::arm64::ID_REG_RL:  return (((*((triton::uint64*)(this->mxcsr))) >> 13) & 1);
          case triton::arch::arm64::ID_REG_RH:  return (((*((triton::uint64*)(this->mxcsr))) >> 14) & 1);
          case triton::arch::arm64::ID_REG_FZ:  return (((*((triton::uint64*)(this->mxcsr))) >> 15) & 1);

          case triton::arch::arm64::ID_REG_CF: return (((*((triton::uint64*)(this->eflags))) >> 0) & 1);
          case triton::arch::arm64::ID_REG_PF: return (((*((triton::uint64*)(this->eflags))) >> 2) & 1);
          case triton::arch::arm64::ID_REG_AF: return (((*((triton::uint64*)(this->eflags))) >> 4) & 1);
          case triton::arch::arm64::ID_REG_ZF: return (((*((triton::uint64*)(this->eflags))) >> 6) & 1);
          case triton::arch::arm64::ID_REG_SF: return (((*((triton::uint64*)(this->eflags))) >> 7) & 1);
          case triton::arch::arm64::ID_REG_TF: return (((*((triton::uint64*)(this->eflags))) >> 8) & 1);
          case triton::arch::arm64::ID_REG_IF: return (((*((triton::uint64*)(this->eflags))) >> 9) & 1);
          case triton::arch::arm64::ID_REG_DF: return (((*((triton::uint64*)(this->eflags))) >> 10) & 1);
          case triton::arch::arm64::ID_REG_OF: return (((*((triton::uint64*)(this->eflags))) >> 11) & 1);

          case triton::arch::arm64::ID_REG_CS: return (*((triton::uint64*)(this->cs)));
          case triton::arch::arm64::ID_REG_DS: return (*((triton::uint64*)(this->ds)));
          case triton::arch::arm64::ID_REG_ES: return (*((triton::uint64*)(this->es)));
          case triton::arch::arm64::ID_REG_FS: return (*((triton::uint64*)(this->fs)));
          case triton::arch::arm64::ID_REG_GS: return (*((triton::uint64*)(this->gs)));
          case triton::arch::arm64::ID_REG_SS: return (*((triton::uint64*)(this->ss)));

          default:
            throw triton::exceptions::Cpu("arm64Cpu::getConcreteRegisterValue(): Invalid register.");
        }

        return value;
      }


      void arm64Cpu::setConcreteMemoryValue(triton::uint64 addr, triton::uint8 value) {
        this->memory[addr] = value;
      }


      void arm64Cpu::setConcreteMemoryValue(const triton::arch::MemoryAccess& mem) {
        triton::uint64 addr = mem.getAddress();
        triton::uint32 size = mem.getSize();
        triton::uint512 cv  = mem.getConcreteValue();

        if (size == 0 || size > DQQWORD_SIZE)
          throw triton::exceptions::Cpu("arm64Cpu::setConcreteMemoryValue(): Invalid size memory.");

        for (triton::uint32 i = 0; i < size; i++) {
          this->memory[addr+i] = (cv & 0xff).convert_to<triton::uint8>();
          cv >>= 8;
        }
      }


      void arm64Cpu::setConcreteMemoryAreaValue(triton::uint64 baseAddr, const std::vector<triton::uint8>& values) {
        for (triton::usize index = 0; index < values.size(); index++) {
          this->memory[baseAddr+index] = values[index];
        }
      }


      void arm64Cpu::setConcreteMemoryAreaValue(triton::uint64 baseAddr, const triton::uint8* area, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          this->memory[baseAddr+index] = area[index];
        }
      }


      void arm64Cpu::setConcreteRegisterValue(const triton::arch::Register& reg) {
        triton::uint512 value = reg.getConcreteValue();

        switch (reg.getId()) {
          case triton::arch::arm64::ID_REG_RAX: (*((triton::uint64*)(this->rax)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EAX: (*((triton::uint32*)(this->rax)))  = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_AX:  (*((triton::uint16*)(this->rax)))  = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_AH:  (*((triton::uint8*)(this->rax+1))) = value.convert_to<triton::uint8>(); break;
          case triton::arch::arm64::ID_REG_AL:  (*((triton::uint8*)(this->rax)))   = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RBX: (*((triton::uint64*)(this->rbx)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EBX: (*((triton::uint32*)(this->rbx)))  = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_BX:  (*((triton::uint16*)(this->rbx)))  = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_BH:  (*((triton::uint8*)(this->rbx+1))) = value.convert_to<triton::uint8>(); break;
          case triton::arch::arm64::ID_REG_BL:  (*((triton::uint8*)(this->rbx)))   = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RCX: (*((triton::uint64*)(this->rcx)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_ECX: (*((triton::uint32*)(this->rcx)))  = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_CX:  (*((triton::uint16*)(this->rcx)))  = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_CH:  (*((triton::uint8*)(this->rcx+1))) = value.convert_to<triton::uint8>(); break;
          case triton::arch::arm64::ID_REG_CL:  (*((triton::uint8*)(this->rcx)))   = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RDX: (*((triton::uint64*)(this->rdx)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EDX: (*((triton::uint32*)(this->rdx)))  = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_DX:  (*((triton::uint16*)(this->rdx)))  = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_DH:  (*((triton::uint8*)(this->rdx+1))) = value.convert_to<triton::uint8>(); break;
          case triton::arch::arm64::ID_REG_DL:  (*((triton::uint8*)(this->rdx)))   = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RDI: (*((triton::uint64*)(this->rdi)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EDI: (*((triton::uint32*)(this->rdi)))  = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_DI:  (*((triton::uint16*)(this->rdi)))  = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_DIL: (*((triton::uint8*)(this->rdi)))   = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RSI: (*((triton::uint64*)(this->rsi))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_ESI: (*((triton::uint32*)(this->rsi))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_SI:  (*((triton::uint16*)(this->rsi))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_SIL: (*((triton::uint8*)(this->rsi)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RSP: (*((triton::uint64*)(this->rsp))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_ESP: (*((triton::uint32*)(this->rsp))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_SP:  (*((triton::uint16*)(this->rsp))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_SPL: (*((triton::uint8*)(this->rsp)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RBP: (*((triton::uint64*)(this->rbp))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EBP: (*((triton::uint32*)(this->rbp))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_BP:  (*((triton::uint16*)(this->rbp))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_BPL: (*((triton::uint8*)(this->rbp)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_RIP: (*((triton::uint64*)(this->rip))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_EIP: (*((triton::uint32*)(this->rip))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_IP:  (*((triton::uint16*)(this->rip))) = value.convert_to<triton::uint16>(); break;

          case triton::arch::arm64::ID_REG_EFLAGS: (*((triton::uint64*)(this->eflags))) = value.convert_to<triton::uint64>(); break;

          case triton::arch::arm64::ID_REG_CF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 0) : b & ~(1 << 0);
            break;
          }
          case triton::arch::arm64::ID_REG_PF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 2) : b & ~(1 << 2);
            break;
          }
          case triton::arch::arm64::ID_REG_AF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 4) : b & ~(1 << 4);
            break;
          }
          case triton::arch::arm64::ID_REG_ZF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 6) : b & ~(1 << 6);
            break;
          }
          case triton::arch::arm64::ID_REG_SF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 7) : b & ~(1 << 7);
            break;
          }
          case triton::arch::arm64::ID_REG_TF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 8) : b & ~(1 << 8);
            break;
          }
          case triton::arch::arm64::ID_REG_IF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 9) : b & ~(1 << 9);
            break;
          }
          case triton::arch::arm64::ID_REG_DF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 10) : b & ~(1 << 10);
            break;
          }
          case triton::arch::arm64::ID_REG_OF: {
            triton::uint64 b = (*((triton::uint64*)(this->eflags)));
            (*((triton::uint64*)(this->eflags))) = value.convert_to<bool>() ? b | (1 << 11) : b & ~(1 << 11);
            break;
          }

          case triton::arch::arm64::ID_REG_R8:  (*((triton::uint64*)(this->r8))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R8D: (*((triton::uint32*)(this->r8))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R8W: (*((triton::uint16*)(this->r8))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R8B: (*((triton::uint8*)(this->r8)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R9:  (*((triton::uint64*)(this->r9))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R9D: (*((triton::uint32*)(this->r9))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R9W: (*((triton::uint16*)(this->r9))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R9B: (*((triton::uint8*)(this->r9)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R10:  (*((triton::uint64*)(this->r10))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R10D: (*((triton::uint32*)(this->r10))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R10W: (*((triton::uint16*)(this->r10))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R10B: (*((triton::uint8*)(this->r10)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R11:  (*((triton::uint64*)(this->r11))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R11D: (*((triton::uint32*)(this->r11))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R11W: (*((triton::uint16*)(this->r11))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R11B: (*((triton::uint8*)(this->r11)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R12:  (*((triton::uint64*)(this->r12))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R12D: (*((triton::uint32*)(this->r12))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R12W: (*((triton::uint16*)(this->r12))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R12B: (*((triton::uint8*)(this->r12)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R13:  (*((triton::uint64*)(this->r13))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R13D: (*((triton::uint32*)(this->r13))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R13W: (*((triton::uint16*)(this->r13))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R13B: (*((triton::uint8*)(this->r13)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R14:  (*((triton::uint64*)(this->r14))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R14D: (*((triton::uint32*)(this->r14))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R14W: (*((triton::uint16*)(this->r14))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R14B: (*((triton::uint8*)(this->r14)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_R15:  (*((triton::uint64*)(this->r15))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_R15D: (*((triton::uint32*)(this->r15))) = value.convert_to<triton::uint32>(); break;
          case triton::arch::arm64::ID_REG_R15W: (*((triton::uint16*)(this->r15))) = value.convert_to<triton::uint16>(); break;
          case triton::arch::arm64::ID_REG_R15B: (*((triton::uint8*)(this->r15)))  = value.convert_to<triton::uint8>(); break;

          case triton::arch::arm64::ID_REG_MM0:  (*((triton::uint64*)(this->mm0))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM1:  (*((triton::uint64*)(this->mm1))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM2:  (*((triton::uint64*)(this->mm2))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM3:  (*((triton::uint64*)(this->mm3))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM4:  (*((triton::uint64*)(this->mm4))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM5:  (*((triton::uint64*)(this->mm5))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM6:  (*((triton::uint64*)(this->mm6))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_MM7:  (*((triton::uint64*)(this->mm7))) = value.convert_to<triton::uint64>(); break;

          case triton::arch::arm64::ID_REG_XMM0:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm0); break;
          case triton::arch::arm64::ID_REG_XMM1:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm1); break;
          case triton::arch::arm64::ID_REG_XMM2:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm2); break;
          case triton::arch::arm64::ID_REG_XMM3:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm3); break;
          case triton::arch::arm64::ID_REG_XMM4:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm4); break;
          case triton::arch::arm64::ID_REG_XMM5:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm5); break;
          case triton::arch::arm64::ID_REG_XMM6:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm6); break;
          case triton::arch::arm64::ID_REG_XMM7:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm7); break;
          case triton::arch::arm64::ID_REG_XMM8:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm8); break;
          case triton::arch::arm64::ID_REG_XMM9:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm9); break;
          case triton::arch::arm64::ID_REG_XMM10: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm10); break;
          case triton::arch::arm64::ID_REG_XMM11: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm11); break;
          case triton::arch::arm64::ID_REG_XMM12: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm12); break;
          case triton::arch::arm64::ID_REG_XMM13: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm13); break;
          case triton::arch::arm64::ID_REG_XMM14: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm14); break;
          case triton::arch::arm64::ID_REG_XMM15: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), this->xmm15); break;

          case triton::arch::arm64::ID_REG_YMM0:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm0); break;
          case triton::arch::arm64::ID_REG_YMM1:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm1); break;
          case triton::arch::arm64::ID_REG_YMM2:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm2); break;
          case triton::arch::arm64::ID_REG_YMM3:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm3); break;
          case triton::arch::arm64::ID_REG_YMM4:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm4); break;
          case triton::arch::arm64::ID_REG_YMM5:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm5); break;
          case triton::arch::arm64::ID_REG_YMM6:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm6); break;
          case triton::arch::arm64::ID_REG_YMM7:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm7); break;
          case triton::arch::arm64::ID_REG_YMM8:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm8); break;
          case triton::arch::arm64::ID_REG_YMM9:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm9); break;
          case triton::arch::arm64::ID_REG_YMM10: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm10); break;
          case triton::arch::arm64::ID_REG_YMM11: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm11); break;
          case triton::arch::arm64::ID_REG_YMM12: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm12); break;
          case triton::arch::arm64::ID_REG_YMM13: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm13); break;
          case triton::arch::arm64::ID_REG_YMM14: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm14); break;
          case triton::arch::arm64::ID_REG_YMM15: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), this->ymm15); break;

          case triton::arch::arm64::ID_REG_ZMM0:  triton::utils::fromUintToBuffer(value, this->zmm0); break;
          case triton::arch::arm64::ID_REG_ZMM1:  triton::utils::fromUintToBuffer(value, this->zmm1); break;
          case triton::arch::arm64::ID_REG_ZMM2:  triton::utils::fromUintToBuffer(value, this->zmm2); break;
          case triton::arch::arm64::ID_REG_ZMM3:  triton::utils::fromUintToBuffer(value, this->zmm3); break;
          case triton::arch::arm64::ID_REG_ZMM4:  triton::utils::fromUintToBuffer(value, this->zmm4); break;
          case triton::arch::arm64::ID_REG_ZMM5:  triton::utils::fromUintToBuffer(value, this->zmm5); break;
          case triton::arch::arm64::ID_REG_ZMM6:  triton::utils::fromUintToBuffer(value, this->zmm6); break;
          case triton::arch::arm64::ID_REG_ZMM7:  triton::utils::fromUintToBuffer(value, this->zmm7); break;
          case triton::arch::arm64::ID_REG_ZMM8:  triton::utils::fromUintToBuffer(value, this->zmm8); break;
          case triton::arch::arm64::ID_REG_ZMM9:  triton::utils::fromUintToBuffer(value, this->zmm9); break;
          case triton::arch::arm64::ID_REG_ZMM10: triton::utils::fromUintToBuffer(value, this->zmm10); break;
          case triton::arch::arm64::ID_REG_ZMM11: triton::utils::fromUintToBuffer(value, this->zmm11); break;
          case triton::arch::arm64::ID_REG_ZMM12: triton::utils::fromUintToBuffer(value, this->zmm12); break;
          case triton::arch::arm64::ID_REG_ZMM13: triton::utils::fromUintToBuffer(value, this->zmm13); break;
          case triton::arch::arm64::ID_REG_ZMM14: triton::utils::fromUintToBuffer(value, this->zmm14); break;
          case triton::arch::arm64::ID_REG_ZMM15: triton::utils::fromUintToBuffer(value, this->zmm15); break;
          case triton::arch::arm64::ID_REG_ZMM16: triton::utils::fromUintToBuffer(value, this->zmm16); break;
          case triton::arch::arm64::ID_REG_ZMM17: triton::utils::fromUintToBuffer(value, this->zmm17); break;
          case triton::arch::arm64::ID_REG_ZMM18: triton::utils::fromUintToBuffer(value, this->zmm18); break;
          case triton::arch::arm64::ID_REG_ZMM19: triton::utils::fromUintToBuffer(value, this->zmm19); break;
          case triton::arch::arm64::ID_REG_ZMM20: triton::utils::fromUintToBuffer(value, this->zmm20); break;
          case triton::arch::arm64::ID_REG_ZMM21: triton::utils::fromUintToBuffer(value, this->zmm21); break;
          case triton::arch::arm64::ID_REG_ZMM22: triton::utils::fromUintToBuffer(value, this->zmm22); break;
          case triton::arch::arm64::ID_REG_ZMM23: triton::utils::fromUintToBuffer(value, this->zmm23); break;
          case triton::arch::arm64::ID_REG_ZMM24: triton::utils::fromUintToBuffer(value, this->zmm24); break;
          case triton::arch::arm64::ID_REG_ZMM25: triton::utils::fromUintToBuffer(value, this->zmm25); break;
          case triton::arch::arm64::ID_REG_ZMM26: triton::utils::fromUintToBuffer(value, this->zmm26); break;
          case triton::arch::arm64::ID_REG_ZMM27: triton::utils::fromUintToBuffer(value, this->zmm27); break;
          case triton::arch::arm64::ID_REG_ZMM28: triton::utils::fromUintToBuffer(value, this->zmm28); break;
          case triton::arch::arm64::ID_REG_ZMM29: triton::utils::fromUintToBuffer(value, this->zmm29); break;
          case triton::arch::arm64::ID_REG_ZMM30: triton::utils::fromUintToBuffer(value, this->zmm30); break;
          case triton::arch::arm64::ID_REG_ZMM31: triton::utils::fromUintToBuffer(value, this->zmm31); break;

          case triton::arch::arm64::ID_REG_MXCSR: (*((triton::uint64*)(this->mxcsr))) = value.convert_to<triton::uint64>(); break;

          case triton::arch::arm64::ID_REG_IE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 0) : b & ~(1 << 0);
            break;
          }
          case triton::arch::arm64::ID_REG_DE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 1) : b & ~(1 << 1);
            break;
          }
          case triton::arch::arm64::ID_REG_ZE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 2) : b & ~(1 << 2);
            break;
          }
          case triton::arch::arm64::ID_REG_OE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 3) : b & ~(1 << 3);
            break;
          }
          case triton::arch::arm64::ID_REG_UE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 4) : b & ~(1 << 4);
            break;
          }
          case triton::arch::arm64::ID_REG_PE: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 5) : b & ~(1 << 5);
            break;
          }
          case triton::arch::arm64::ID_REG_DAZ: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 6) : b & ~(1 << 6);
            break;
          }
          case triton::arch::arm64::ID_REG_IM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 7) : b & ~(1 << 7);
            break;
          }
          case triton::arch::arm64::ID_REG_DM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 8) : b & ~(1 << 8);
            break;
          }
          case triton::arch::arm64::ID_REG_ZM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 9) : b & ~(1 << 9);
            break;
          }
          case triton::arch::arm64::ID_REG_OM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 10) : b & ~(1 << 10);
            break;
          }
          case triton::arch::arm64::ID_REG_UM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 11) : b & ~(1 << 11);
            break;
          }
          case triton::arch::arm64::ID_REG_PM: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 12) : b & ~(1 << 12);
            break;
          }
          case triton::arch::arm64::ID_REG_RL: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 13) : b & ~(1 << 13);
            break;
          }
          case triton::arch::arm64::ID_REG_RH: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 14) : b & ~(1 << 14);
            break;
          }
          case triton::arch::arm64::ID_REG_FZ: {
            triton::uint64 b = (*((triton::uint64*)(this->mxcsr)));
            (*((triton::uint64*)(this->mxcsr))) = value.convert_to<bool>() ? b | (1 << 15) : b & ~(1 << 15);
            break;
          }

          case triton::arch::arm64::ID_REG_CR0:  (*((triton::uint64*)(this->cr0)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR1:  (*((triton::uint64*)(this->cr1)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR2:  (*((triton::uint64*)(this->cr2)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR3:  (*((triton::uint64*)(this->cr3)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR4:  (*((triton::uint64*)(this->cr4)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR5:  (*((triton::uint64*)(this->cr5)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR6:  (*((triton::uint64*)(this->cr6)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR7:  (*((triton::uint64*)(this->cr7)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR8:  (*((triton::uint64*)(this->cr8)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR9:  (*((triton::uint64*)(this->cr9)))  = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR10: (*((triton::uint64*)(this->cr10))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR11: (*((triton::uint64*)(this->cr11))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR12: (*((triton::uint64*)(this->cr12))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR13: (*((triton::uint64*)(this->cr13))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR14: (*((triton::uint64*)(this->cr14))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_CR15: (*((triton::uint64*)(this->cr15))) = value.convert_to<triton::uint64>(); break;

          case triton::arch::arm64::ID_REG_CS:  (*((triton::uint64*)(this->cs))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_DS:  (*((triton::uint64*)(this->ds))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_ES:  (*((triton::uint64*)(this->es))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_FS:  (*((triton::uint64*)(this->fs))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_GS:  (*((triton::uint64*)(this->gs))) = value.convert_to<triton::uint64>(); break;
          case triton::arch::arm64::ID_REG_SS:  (*((triton::uint64*)(this->ss))) = value.convert_to<triton::uint64>(); break;

          default:
            throw triton::exceptions::Cpu("arm64Cpu:setConcreteRegisterValue(): Invalid register.");
        }
      }


      bool arm64Cpu::isMemoryMapped(triton::uint64 baseAddr, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          if (this->memory.find(baseAddr + index) == this->memory.end())
            return false;
        }
        return true;
      }


      void arm64Cpu::unmapMemory(triton::uint64 baseAddr, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          if (this->memory.find(baseAddr + index) != this->memory.end())
            this->memory.erase(baseAddr + index);
        }
      }

    }; /* arm64 namespace */
  }; /* arch namespace */
}; /* triton namespace */

