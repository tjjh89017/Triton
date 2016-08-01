//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <api.hpp>
#include <cpuSize.hpp>
#include <externalLibs.hpp>
#include <arm64Specifications.hpp>



namespace triton {
  namespace arch {
    namespace arm64 {

      /*
       * Inside semantics, sometime we have to use references to registers.
       * TRITON_ARM64_REG_RAX, TRITON_ARM64_REG_RBX, ..., TRITON_ARM64_REG_AF...
       * are now available for a temporary access to the triton::arch::Register
       * class. By default, these ARM64_REG are empty. We must use init32 or init64 before.
       */

      triton::arch::Register arm64_reg_invalid = triton::arch::Register();

      triton::arch::Register arm64_reg_rax     = triton::arch::Register();
      triton::arch::Register arm64_reg_eax     = triton::arch::Register();
      triton::arch::Register arm64_reg_ax      = triton::arch::Register();
      triton::arch::Register arm64_reg_ah      = triton::arch::Register();
      triton::arch::Register arm64_reg_al      = triton::arch::Register();

      triton::arch::Register arm64_reg_rbx     = triton::arch::Register();
      triton::arch::Register arm64_reg_ebx     = triton::arch::Register();
      triton::arch::Register arm64_reg_bx      = triton::arch::Register();
      triton::arch::Register arm64_reg_bh      = triton::arch::Register();
      triton::arch::Register arm64_reg_bl      = triton::arch::Register();

      triton::arch::Register arm64_reg_rcx     = triton::arch::Register();
      triton::arch::Register arm64_reg_ecx     = triton::arch::Register();
      triton::arch::Register arm64_reg_cx      = triton::arch::Register();
      triton::arch::Register arm64_reg_ch      = triton::arch::Register();
      triton::arch::Register arm64_reg_cl      = triton::arch::Register();

      triton::arch::Register arm64_reg_rdx     = triton::arch::Register();
      triton::arch::Register arm64_reg_edx     = triton::arch::Register();
      triton::arch::Register arm64_reg_dx      = triton::arch::Register();
      triton::arch::Register arm64_reg_dh      = triton::arch::Register();
      triton::arch::Register arm64_reg_dl      = triton::arch::Register();

      triton::arch::Register arm64_reg_rdi     = triton::arch::Register();
      triton::arch::Register arm64_reg_edi     = triton::arch::Register();
      triton::arch::Register arm64_reg_di      = triton::arch::Register();
      triton::arch::Register arm64_reg_dil     = triton::arch::Register();

      triton::arch::Register arm64_reg_rsi     = triton::arch::Register();
      triton::arch::Register arm64_reg_esi     = triton::arch::Register();
      triton::arch::Register arm64_reg_si      = triton::arch::Register();
      triton::arch::Register arm64_reg_sil     = triton::arch::Register();

      triton::arch::Register arm64_reg_rsp     = triton::arch::Register();
      triton::arch::Register arm64_reg_esp     = triton::arch::Register();
      triton::arch::Register arm64_reg_sp      = triton::arch::Register();
      triton::arch::Register arm64_reg_spl     = triton::arch::Register();
      triton::arch::Register arm64_reg_stack   = triton::arch::Register();

      triton::arch::Register arm64_reg_rbp     = triton::arch::Register();
      triton::arch::Register arm64_reg_ebp     = triton::arch::Register();
      triton::arch::Register arm64_reg_bp      = triton::arch::Register();
      triton::arch::Register arm64_reg_bpl     = triton::arch::Register();

      triton::arch::Register arm64_reg_rip     = triton::arch::Register();
      triton::arch::Register arm64_reg_eip     = triton::arch::Register();
      triton::arch::Register arm64_reg_ip      = triton::arch::Register();
      triton::arch::Register arm64_reg_pc      = triton::arch::Register();

      triton::arch::Register arm64_reg_eflags  = triton::arch::Register();

      triton::arch::Register arm64_reg_r8      = triton::arch::Register();
      triton::arch::Register arm64_reg_r8d     = triton::arch::Register();
      triton::arch::Register arm64_reg_r8w     = triton::arch::Register();
      triton::arch::Register arm64_reg_r8b     = triton::arch::Register();

      triton::arch::Register arm64_reg_r9      = triton::arch::Register();
      triton::arch::Register arm64_reg_r9d     = triton::arch::Register();
      triton::arch::Register arm64_reg_r9w     = triton::arch::Register();
      triton::arch::Register arm64_reg_r9b     = triton::arch::Register();

      triton::arch::Register arm64_reg_r10     = triton::arch::Register();
      triton::arch::Register arm64_reg_r10d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r10w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r10b    = triton::arch::Register();

      triton::arch::Register arm64_reg_r11     = triton::arch::Register();
      triton::arch::Register arm64_reg_r11d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r11w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r11b    = triton::arch::Register();

      triton::arch::Register arm64_reg_r12     = triton::arch::Register();
      triton::arch::Register arm64_reg_r12d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r12w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r12b    = triton::arch::Register();

      triton::arch::Register arm64_reg_r13     = triton::arch::Register();
      triton::arch::Register arm64_reg_r13d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r13w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r13b    = triton::arch::Register();

      triton::arch::Register arm64_reg_r14     = triton::arch::Register();
      triton::arch::Register arm64_reg_r14d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r14w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r14b    = triton::arch::Register();

      triton::arch::Register arm64_reg_r15     = triton::arch::Register();
      triton::arch::Register arm64_reg_r15d    = triton::arch::Register();
      triton::arch::Register arm64_reg_r15w    = triton::arch::Register();
      triton::arch::Register arm64_reg_r15b    = triton::arch::Register();

      triton::arch::Register arm64_reg_mm0     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm1     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm2     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm3     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm4     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm5     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm6     = triton::arch::Register();
      triton::arch::Register arm64_reg_mm7     = triton::arch::Register();

      triton::arch::Register arm64_reg_xmm0    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm1    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm2    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm3    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm4    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm5    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm6    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm7    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm8    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm9    = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm10   = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm11   = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm12   = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm13   = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm14   = triton::arch::Register();
      triton::arch::Register arm64_reg_xmm15   = triton::arch::Register();

      triton::arch::Register arm64_reg_ymm0    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm1    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm2    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm3    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm4    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm5    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm6    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm7    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm8    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm9    = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm10   = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm11   = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm12   = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm13   = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm14   = triton::arch::Register();
      triton::arch::Register arm64_reg_ymm15   = triton::arch::Register();

      triton::arch::Register arm64_reg_zmm0    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm1    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm2    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm3    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm4    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm5    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm6    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm7    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm8    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm9    = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm10   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm11   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm12   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm13   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm14   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm15   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm16   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm17   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm18   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm19   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm20   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm21   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm22   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm23   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm24   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm25   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm26   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm27   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm28   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm29   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm30   = triton::arch::Register();
      triton::arch::Register arm64_reg_zmm31   = triton::arch::Register();

      triton::arch::Register arm64_reg_mxcsr   = triton::arch::Register();

      triton::arch::Register arm64_reg_cr0    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr1    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr2    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr3    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr4    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr5    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr6    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr7    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr8    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr9    = triton::arch::Register();
      triton::arch::Register arm64_reg_cr10   = triton::arch::Register();
      triton::arch::Register arm64_reg_cr11   = triton::arch::Register();
      triton::arch::Register arm64_reg_cr12   = triton::arch::Register();
      triton::arch::Register arm64_reg_cr13   = triton::arch::Register();
      triton::arch::Register arm64_reg_cr14   = triton::arch::Register();
      triton::arch::Register arm64_reg_cr15   = triton::arch::Register();

      triton::arch::Register arm64_reg_ie      = triton::arch::Register();
      triton::arch::Register arm64_reg_de      = triton::arch::Register();
      triton::arch::Register arm64_reg_ze      = triton::arch::Register();
      triton::arch::Register arm64_reg_oe      = triton::arch::Register();
      triton::arch::Register arm64_reg_ue      = triton::arch::Register();
      triton::arch::Register arm64_reg_pe      = triton::arch::Register();
      triton::arch::Register arm64_reg_daz     = triton::arch::Register();
      triton::arch::Register arm64_reg_im      = triton::arch::Register();
      triton::arch::Register arm64_reg_dm      = triton::arch::Register();
      triton::arch::Register arm64_reg_zm      = triton::arch::Register();
      triton::arch::Register arm64_reg_om      = triton::arch::Register();
      triton::arch::Register arm64_reg_um      = triton::arch::Register();
      triton::arch::Register arm64_reg_pm      = triton::arch::Register();
      triton::arch::Register arm64_reg_rl      = triton::arch::Register();
      triton::arch::Register arm64_reg_rh      = triton::arch::Register();
      triton::arch::Register arm64_reg_fz      = triton::arch::Register();

      triton::arch::Register arm64_reg_af      = triton::arch::Register();
      triton::arch::Register arm64_reg_cf      = triton::arch::Register();
      triton::arch::Register arm64_reg_df      = triton::arch::Register();
      triton::arch::Register arm64_reg_if      = triton::arch::Register();
      triton::arch::Register arm64_reg_of      = triton::arch::Register();
      triton::arch::Register arm64_reg_pf      = triton::arch::Register();
      triton::arch::Register arm64_reg_sf      = triton::arch::Register();
      triton::arch::Register arm64_reg_tf      = triton::arch::Register();
      triton::arch::Register arm64_reg_zf      = triton::arch::Register();

      triton::arch::Register arm64_reg_cs      = triton::arch::Register();
      triton::arch::Register arm64_reg_ds      = triton::arch::Register();
      triton::arch::Register arm64_reg_es      = triton::arch::Register();
      triton::arch::Register arm64_reg_fs      = triton::arch::Register();
      triton::arch::Register arm64_reg_gs      = triton::arch::Register();
      triton::arch::Register arm64_reg_ss      = triton::arch::Register();


      triton::arch::Register* arm64_regs[triton::arch::arm64::ID_REG_LAST_ITEM] = {
        &TRITON_ARM64_REG_INVALID,
        &TRITON_ARM64_REG_RAX,
        &TRITON_ARM64_REG_RBX,
        &TRITON_ARM64_REG_RCX,
        &TRITON_ARM64_REG_RDX,
        &TRITON_ARM64_REG_RDI,
        &TRITON_ARM64_REG_RSI,
        &TRITON_ARM64_REG_RBP,
        &TRITON_ARM64_REG_RSP,
        &TRITON_ARM64_REG_RIP,
        &TRITON_ARM64_REG_EFLAGS,
        &TRITON_ARM64_REG_R8,
        &TRITON_ARM64_REG_R8D,
        &TRITON_ARM64_REG_R8W,
        &TRITON_ARM64_REG_R8B,
        &TRITON_ARM64_REG_R9,
        &TRITON_ARM64_REG_R9D,
        &TRITON_ARM64_REG_R9W,
        &TRITON_ARM64_REG_R9B,
        &TRITON_ARM64_REG_R10,
        &TRITON_ARM64_REG_R10D,
        &TRITON_ARM64_REG_R10W,
        &TRITON_ARM64_REG_R10B,
        &TRITON_ARM64_REG_R11,
        &TRITON_ARM64_REG_R11D,
        &TRITON_ARM64_REG_R11W,
        &TRITON_ARM64_REG_R11B,
        &TRITON_ARM64_REG_R12,
        &TRITON_ARM64_REG_R12D,
        &TRITON_ARM64_REG_R12W,
        &TRITON_ARM64_REG_R12B,
        &TRITON_ARM64_REG_R13,
        &TRITON_ARM64_REG_R13D,
        &TRITON_ARM64_REG_R13W,
        &TRITON_ARM64_REG_R13B,
        &TRITON_ARM64_REG_R14,
        &TRITON_ARM64_REG_R14D,
        &TRITON_ARM64_REG_R14W,
        &TRITON_ARM64_REG_R14B,
        &TRITON_ARM64_REG_R15,
        &TRITON_ARM64_REG_R15D,
        &TRITON_ARM64_REG_R15W,
        &TRITON_ARM64_REG_R15B,
        &TRITON_ARM64_REG_EAX,
        &TRITON_ARM64_REG_AX,
        &TRITON_ARM64_REG_AH,
        &TRITON_ARM64_REG_AL,
        &TRITON_ARM64_REG_EBX,
        &TRITON_ARM64_REG_BX,
        &TRITON_ARM64_REG_BH,
        &TRITON_ARM64_REG_BL,
        &TRITON_ARM64_REG_ECX,
        &TRITON_ARM64_REG_CX,
        &TRITON_ARM64_REG_CH,
        &TRITON_ARM64_REG_CL,
        &TRITON_ARM64_REG_EDX,
        &TRITON_ARM64_REG_DX,
        &TRITON_ARM64_REG_DH,
        &TRITON_ARM64_REG_DL,
        &TRITON_ARM64_REG_EDI,
        &TRITON_ARM64_REG_DI,
        &TRITON_ARM64_REG_DIL,
        &TRITON_ARM64_REG_ESI,
        &TRITON_ARM64_REG_SI,
        &TRITON_ARM64_REG_SIL,
        &TRITON_ARM64_REG_EBP,
        &TRITON_ARM64_REG_BP,
        &TRITON_ARM64_REG_BPL,
        &TRITON_ARM64_REG_ESP,
        &TRITON_ARM64_REG_SP,
        &TRITON_ARM64_REG_SPL,
        &TRITON_ARM64_REG_EIP,
        &TRITON_ARM64_REG_IP,
        &TRITON_ARM64_REG_MM0,
        &TRITON_ARM64_REG_MM1,
        &TRITON_ARM64_REG_MM2,
        &TRITON_ARM64_REG_MM3,
        &TRITON_ARM64_REG_MM4,
        &TRITON_ARM64_REG_MM5,
        &TRITON_ARM64_REG_MM6,
        &TRITON_ARM64_REG_MM7,
        &TRITON_ARM64_REG_XMM0,
        &TRITON_ARM64_REG_XMM1,
        &TRITON_ARM64_REG_XMM2,
        &TRITON_ARM64_REG_XMM3,
        &TRITON_ARM64_REG_XMM4,
        &TRITON_ARM64_REG_XMM5,
        &TRITON_ARM64_REG_XMM6,
        &TRITON_ARM64_REG_XMM7,
        &TRITON_ARM64_REG_XMM8,
        &TRITON_ARM64_REG_XMM9,
        &TRITON_ARM64_REG_XMM10,
        &TRITON_ARM64_REG_XMM11,
        &TRITON_ARM64_REG_XMM12,
        &TRITON_ARM64_REG_XMM13,
        &TRITON_ARM64_REG_XMM14,
        &TRITON_ARM64_REG_XMM15,
        &TRITON_ARM64_REG_YMM0,
        &TRITON_ARM64_REG_YMM1,
        &TRITON_ARM64_REG_YMM2,
        &TRITON_ARM64_REG_YMM3,
        &TRITON_ARM64_REG_YMM4,
        &TRITON_ARM64_REG_YMM5,
        &TRITON_ARM64_REG_YMM6,
        &TRITON_ARM64_REG_YMM7,
        &TRITON_ARM64_REG_YMM8,
        &TRITON_ARM64_REG_YMM9,
        &TRITON_ARM64_REG_YMM10,
        &TRITON_ARM64_REG_YMM11,
        &TRITON_ARM64_REG_YMM12,
        &TRITON_ARM64_REG_YMM13,
        &TRITON_ARM64_REG_YMM14,
        &TRITON_ARM64_REG_YMM15,
        &TRITON_ARM64_REG_ZMM0,
        &TRITON_ARM64_REG_ZMM1,
        &TRITON_ARM64_REG_ZMM2,
        &TRITON_ARM64_REG_ZMM3,
        &TRITON_ARM64_REG_ZMM4,
        &TRITON_ARM64_REG_ZMM5,
        &TRITON_ARM64_REG_ZMM6,
        &TRITON_ARM64_REG_ZMM7,
        &TRITON_ARM64_REG_ZMM8,
        &TRITON_ARM64_REG_ZMM9,
        &TRITON_ARM64_REG_ZMM10,
        &TRITON_ARM64_REG_ZMM11,
        &TRITON_ARM64_REG_ZMM12,
        &TRITON_ARM64_REG_ZMM13,
        &TRITON_ARM64_REG_ZMM14,
        &TRITON_ARM64_REG_ZMM15,
        &TRITON_ARM64_REG_ZMM16,
        &TRITON_ARM64_REG_ZMM17,
        &TRITON_ARM64_REG_ZMM18,
        &TRITON_ARM64_REG_ZMM19,
        &TRITON_ARM64_REG_ZMM20,
        &TRITON_ARM64_REG_ZMM21,
        &TRITON_ARM64_REG_ZMM22,
        &TRITON_ARM64_REG_ZMM23,
        &TRITON_ARM64_REG_ZMM24,
        &TRITON_ARM64_REG_ZMM25,
        &TRITON_ARM64_REG_ZMM26,
        &TRITON_ARM64_REG_ZMM27,
        &TRITON_ARM64_REG_ZMM28,
        &TRITON_ARM64_REG_ZMM29,
        &TRITON_ARM64_REG_ZMM30,
        &TRITON_ARM64_REG_ZMM31,
        &TRITON_ARM64_REG_MXCSR,
        &TRITON_ARM64_REG_CR0,
        &TRITON_ARM64_REG_CR1,
        &TRITON_ARM64_REG_CR2,
        &TRITON_ARM64_REG_CR3,
        &TRITON_ARM64_REG_CR4,
        &TRITON_ARM64_REG_CR5,
        &TRITON_ARM64_REG_CR6,
        &TRITON_ARM64_REG_CR7,
        &TRITON_ARM64_REG_CR8,
        &TRITON_ARM64_REG_CR9,
        &TRITON_ARM64_REG_CR10,
        &TRITON_ARM64_REG_CR11,
        &TRITON_ARM64_REG_CR12,
        &TRITON_ARM64_REG_CR13,
        &TRITON_ARM64_REG_CR14,
        &TRITON_ARM64_REG_CR15,
        &TRITON_ARM64_REG_IE,
        &TRITON_ARM64_REG_DE,
        &TRITON_ARM64_REG_ZE,
        &TRITON_ARM64_REG_OE,
        &TRITON_ARM64_REG_UE,
        &TRITON_ARM64_REG_PE,
        &TRITON_ARM64_REG_DAZ,
        &TRITON_ARM64_REG_IM,
        &TRITON_ARM64_REG_DM,
        &TRITON_ARM64_REG_ZM,
        &TRITON_ARM64_REG_OM,
        &TRITON_ARM64_REG_UM,
        &TRITON_ARM64_REG_PM,
        &TRITON_ARM64_REG_RL,
        &TRITON_ARM64_REG_RH,
        &TRITON_ARM64_REG_FZ,
        &TRITON_ARM64_REG_AF,
        &TRITON_ARM64_REG_CF,
        &TRITON_ARM64_REG_DF,
        &TRITON_ARM64_REG_IF,
        &TRITON_ARM64_REG_OF,
        &TRITON_ARM64_REG_PF,
        &TRITON_ARM64_REG_SF,
        &TRITON_ARM64_REG_TF,
        &TRITON_ARM64_REG_ZF,
        &TRITON_ARM64_REG_CS,
        &TRITON_ARM64_REG_DS,
        &TRITON_ARM64_REG_ES,
        &TRITON_ARM64_REG_FS,
        &TRITON_ARM64_REG_GS,
        &TRITON_ARM64_REG_SS
      };


      /* Returns all information about a register from its triton id */
      std::tuple<std::string, triton::uint32, triton::uint32, triton::uint32> registerIdToRegisterInformation(triton::uint32 reg) {

        std::tuple<std::string, triton::uint32, triton::uint32, triton::uint32> ret;

        std::get<0>(ret) = "unknown"; /* name           */
        std::get<1>(ret) = 0;         /* highest bit    */
        std::get<2>(ret) = 0;         /* lower bit      */
        std::get<3>(ret) = 0;         /* higest reg id  */

        if (triton::api.getArchitecture() == triton::arch::ARCH_INVALID)
          return ret;

        switch (reg) {

          case triton::arch::arm64::ID_REG_RAX:
            std::get<0>(ret) = "rax";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RAX;
            break;

          case triton::arch::arm64::ID_REG_EAX:
            std::get<0>(ret) = "eax";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RAX : triton::arch::arm64::ID_REG_EAX;
            break;

          case triton::arch::arm64::ID_REG_AX:
            std::get<0>(ret) = "ax";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RAX : triton::arch::arm64::ID_REG_EAX;
            break;

          case triton::arch::arm64::ID_REG_AH:
            std::get<0>(ret) = "ah";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = BYTE_SIZE_BIT;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RAX : triton::arch::arm64::ID_REG_EAX;
            break;

          case triton::arch::arm64::ID_REG_AL:
            std::get<0>(ret) = "al";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RAX : triton::arch::arm64::ID_REG_EAX;
            break;

          case triton::arch::arm64::ID_REG_RBX:
            std::get<0>(ret) = "rbx";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RBX;
            break;

          case triton::arch::arm64::ID_REG_EBX:
            std::get<0>(ret) = "ebx";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBX : triton::arch::arm64::ID_REG_EBX;
            break;

          case triton::arch::arm64::ID_REG_BX:
            std::get<0>(ret) = "bx";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBX : triton::arch::arm64::ID_REG_EBX;
            break;

          case triton::arch::arm64::ID_REG_BH:
            std::get<0>(ret) = "bh";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = BYTE_SIZE_BIT;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBX : triton::arch::arm64::ID_REG_EBX;
            break;

          case triton::arch::arm64::ID_REG_BL:
            std::get<0>(ret) = "bl";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBX : triton::arch::arm64::ID_REG_EBX;
            break;

          case triton::arch::arm64::ID_REG_RCX:
            std::get<0>(ret) = "rcx";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RCX;
            break;

          case triton::arch::arm64::ID_REG_ECX:
            std::get<0>(ret) = "ecx";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RCX : triton::arch::arm64::ID_REG_ECX;
            break;

          case triton::arch::arm64::ID_REG_CX:
            std::get<0>(ret) = "cx";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RCX : triton::arch::arm64::ID_REG_ECX;
            break;

          case triton::arch::arm64::ID_REG_CH:
            std::get<0>(ret) = "ch";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = BYTE_SIZE_BIT;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RCX : triton::arch::arm64::ID_REG_ECX;
            break;

          case triton::arch::arm64::ID_REG_CL:
            std::get<0>(ret) = "cl";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RCX : triton::arch::arm64::ID_REG_ECX;
            break;

          case triton::arch::arm64::ID_REG_RDX:
            std::get<0>(ret) = "rdx";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RDX;
            break;

          case triton::arch::arm64::ID_REG_EDX:
            std::get<0>(ret) = "edx";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDX : triton::arch::arm64::ID_REG_EDX;
            break;

          case triton::arch::arm64::ID_REG_DX:
            std::get<0>(ret) = "dx";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDX : triton::arch::arm64::ID_REG_EDX;
            break;

          case triton::arch::arm64::ID_REG_DH:
            std::get<0>(ret) = "dh";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = BYTE_SIZE_BIT;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDX : triton::arch::arm64::ID_REG_EDX;
            break;

          case triton::arch::arm64::ID_REG_DL:
            std::get<0>(ret) = "dl";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDX : triton::arch::arm64::ID_REG_EDX;
            break;

          case triton::arch::arm64::ID_REG_RDI:
            std::get<0>(ret) = "rdi";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RDI;
            break;

          case triton::arch::arm64::ID_REG_EDI:
            std::get<0>(ret) = "edi";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDI : triton::arch::arm64::ID_REG_EDI;
            break;

          case triton::arch::arm64::ID_REG_DI:
            std::get<0>(ret) = "di";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDI : triton::arch::arm64::ID_REG_EDI;
            break;

          case triton::arch::arm64::ID_REG_DIL:
            std::get<0>(ret) = "dil";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RDI : triton::arch::arm64::ID_REG_EDI;
            break;

          case triton::arch::arm64::ID_REG_RSI:
            std::get<0>(ret) = "rsi";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RSI;
            break;

          case triton::arch::arm64::ID_REG_ESI:
            std::get<0>(ret) = "esi";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSI : triton::arch::arm64::ID_REG_ESI;
            break;

          case triton::arch::arm64::ID_REG_SI:
            std::get<0>(ret) = "si";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSI : triton::arch::arm64::ID_REG_ESI;
            break;

          case triton::arch::arm64::ID_REG_SIL:
            std::get<0>(ret) = "sil";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSI : triton::arch::arm64::ID_REG_ESI;
            break;

          case triton::arch::arm64::ID_REG_RBP:
            std::get<0>(ret) = "rbp";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RBP;
            break;

          case triton::arch::arm64::ID_REG_EBP:
            std::get<0>(ret) = "ebp";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBP : triton::arch::arm64::ID_REG_EBP;
            break;

          case triton::arch::arm64::ID_REG_BP:
            std::get<0>(ret) = "bp";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBP : triton::arch::arm64::ID_REG_EBP;
            break;

          case triton::arch::arm64::ID_REG_BPL:
            std::get<0>(ret) = "bpl";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RBP : triton::arch::arm64::ID_REG_EBP;
            break;

          case triton::arch::arm64::ID_REG_RSP:
            std::get<0>(ret) = "rsp";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RSP;
            break;

          case triton::arch::arm64::ID_REG_ESP:
            std::get<0>(ret) = "esp";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSP : triton::arch::arm64::ID_REG_ESP;
            break;

          case triton::arch::arm64::ID_REG_SP:
            std::get<0>(ret) = "sp";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSP : triton::arch::arm64::ID_REG_ESP;
            break;

          case triton::arch::arm64::ID_REG_SPL:
            std::get<0>(ret) = "spl";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RSP : triton::arch::arm64::ID_REG_ESP;
            break;

          case triton::arch::arm64::ID_REG_RIP:
            std::get<0>(ret) = "rip";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RIP;
            break;

          case triton::arch::arm64::ID_REG_EIP:
            std::get<0>(ret) = "eip";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RIP : triton::arch::arm64::ID_REG_EIP;
            break;

          case triton::arch::arm64::ID_REG_IP:
            std::get<0>(ret) = "ip";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? triton::arch::arm64::ID_REG_RIP : triton::arch::arm64::ID_REG_EIP;
            break;

          case triton::arch::arm64::ID_REG_EFLAGS:
            std::get<0>(ret) = "eflags";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_EFLAGS;
            break;

          case triton::arch::arm64::ID_REG_R8:
            std::get<0>(ret) = "r8";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R8;
            break;

          case triton::arch::arm64::ID_REG_R8D:
            std::get<0>(ret) = "r8d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R8;
            break;

          case triton::arch::arm64::ID_REG_R8W:
            std::get<0>(ret) = "r8w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R8;
            break;

          case triton::arch::arm64::ID_REG_R8B:
            std::get<0>(ret) = "r8b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R8;
            break;

          case triton::arch::arm64::ID_REG_R9:
            std::get<0>(ret) = "r9";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R9;
            break;

          case triton::arch::arm64::ID_REG_R9D:
            std::get<0>(ret) = "r9d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R9;
            break;

          case triton::arch::arm64::ID_REG_R9W:
            std::get<0>(ret) = "r9w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R9;
            break;

          case triton::arch::arm64::ID_REG_R9B:
            std::get<0>(ret) = "r9b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R9;
            break;

          case triton::arch::arm64::ID_REG_R10:
            std::get<0>(ret) = "r10";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R10;
            break;

          case triton::arch::arm64::ID_REG_R10D:
            std::get<0>(ret) = "r10d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R10;
            break;

          case triton::arch::arm64::ID_REG_R10W:
            std::get<0>(ret) = "r10w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R10;
            break;

          case triton::arch::arm64::ID_REG_R10B:
            std::get<0>(ret) = "r10b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R10;
            break;

          case triton::arch::arm64::ID_REG_R11:
            std::get<0>(ret) = "r11";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R11;
            break;

          case triton::arch::arm64::ID_REG_R11D:
            std::get<0>(ret) = "r11d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R11;
            break;

          case triton::arch::arm64::ID_REG_R11W:
            std::get<0>(ret) = "r11w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R11;
            break;

          case triton::arch::arm64::ID_REG_R11B:
            std::get<0>(ret) = "r11b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R11;
            break;

          case triton::arch::arm64::ID_REG_R12:
            std::get<0>(ret) = "r12";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R12;
            break;

          case triton::arch::arm64::ID_REG_R12D:
            std::get<0>(ret) = "r12d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R12;
            break;

          case triton::arch::arm64::ID_REG_R12W:
            std::get<0>(ret) = "r12w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R12;
            break;

          case triton::arch::arm64::ID_REG_R12B:
            std::get<0>(ret) = "r12b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R12;
            break;

          case triton::arch::arm64::ID_REG_R13:
            std::get<0>(ret) = "r13";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R13;
            break;

          case triton::arch::arm64::ID_REG_R13D:
            std::get<0>(ret) = "r13d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R13;
            break;

          case triton::arch::arm64::ID_REG_R13W:
            std::get<0>(ret) = "r13w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R13;
            break;

          case triton::arch::arm64::ID_REG_R13B:
            std::get<0>(ret) = "r13b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R13;
            break;

          case triton::arch::arm64::ID_REG_R14:
            std::get<0>(ret) = "r14";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R14;
            break;

          case triton::arch::arm64::ID_REG_R14D:
            std::get<0>(ret) = "r14d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R14;
            break;

          case triton::arch::arm64::ID_REG_R14W:
            std::get<0>(ret) = "r14w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R14;
            break;

          case triton::arch::arm64::ID_REG_R14B:
            std::get<0>(ret) = "r14b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R14;
            break;

          case triton::arch::arm64::ID_REG_R15:
            std::get<0>(ret) = "r15";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R15;
            break;

          case triton::arch::arm64::ID_REG_R15D:
            std::get<0>(ret) = "r15d";
            std::get<1>(ret) = DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R15;
            break;

          case triton::arch::arm64::ID_REG_R15W:
            std::get<0>(ret) = "r15w";
            std::get<1>(ret) = WORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R15;
            break;

          case triton::arch::arm64::ID_REG_R15B:
            std::get<0>(ret) = "r15b";
            std::get<1>(ret) = BYTE_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_R15;
            break;

          case triton::arch::arm64::ID_REG_MM0:
            std::get<0>(ret) = "mm0";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM0;
            break;

          case triton::arch::arm64::ID_REG_MM1:
            std::get<0>(ret) = "mm1";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM1;
            break;

          case triton::arch::arm64::ID_REG_MM2:
            std::get<0>(ret) = "mm2";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM2;
            break;

          case triton::arch::arm64::ID_REG_MM3:
            std::get<0>(ret) = "mm3";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM3;
            break;

          case triton::arch::arm64::ID_REG_MM4:
            std::get<0>(ret) = "mm4";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM4;
            break;

          case triton::arch::arm64::ID_REG_MM5:
            std::get<0>(ret) = "mm5";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM5;
            break;

          case triton::arch::arm64::ID_REG_MM6:
            std::get<0>(ret) = "mm6";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM6;
            break;

          case triton::arch::arm64::ID_REG_MM7:
            std::get<0>(ret) = "mm7";
            std::get<1>(ret) = QWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MM7;
            break;

          case triton::arch::arm64::ID_REG_XMM0:
            std::get<0>(ret) = "xmm0";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM0;
            break;

          case triton::arch::arm64::ID_REG_XMM1:
            std::get<0>(ret) = "xmm1";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM1;
            break;

          case triton::arch::arm64::ID_REG_XMM2:
            std::get<0>(ret) = "xmm2";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM2;
            break;

          case triton::arch::arm64::ID_REG_XMM3:
            std::get<0>(ret) = "xmm3";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM3;
            break;

          case triton::arch::arm64::ID_REG_XMM4:
            std::get<0>(ret) = "xmm4";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM4;
            break;

          case triton::arch::arm64::ID_REG_XMM5:
            std::get<0>(ret) = "xmm5";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM5;
            break;

          case triton::arch::arm64::ID_REG_XMM6:
            std::get<0>(ret) = "xmm6";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM6;
            break;

          case triton::arch::arm64::ID_REG_XMM7:
            std::get<0>(ret) = "xmm7";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM7;
            break;

          case triton::arch::arm64::ID_REG_XMM8:
            std::get<0>(ret) = "xmm8";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM8;
            break;

          case triton::arch::arm64::ID_REG_XMM9:
            std::get<0>(ret) = "xmm9";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM9;
            break;

          case triton::arch::arm64::ID_REG_XMM10:
            std::get<0>(ret) = "xmm10";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM10;
            break;

          case triton::arch::arm64::ID_REG_XMM11:
            std::get<0>(ret) = "xmm11";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM11;
            break;

          case triton::arch::arm64::ID_REG_XMM12:
            std::get<0>(ret) = "xmm12";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM12;
            break;

          case triton::arch::arm64::ID_REG_XMM13:
            std::get<0>(ret) = "xmm13";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM13;
            break;

          case triton::arch::arm64::ID_REG_XMM14:
            std::get<0>(ret) = "xmm14";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM14;
            break;

          case triton::arch::arm64::ID_REG_XMM15:
            std::get<0>(ret) = "xmm15";
            std::get<1>(ret) = DQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_XMM15;
            break;

          case triton::arch::arm64::ID_REG_YMM0:
            std::get<0>(ret) = "ymm0";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM0;
            break;

          case triton::arch::arm64::ID_REG_YMM1:
            std::get<0>(ret) = "ymm1";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM1;
            break;

          case triton::arch::arm64::ID_REG_YMM2:
            std::get<0>(ret) = "ymm2";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM2;
            break;

          case triton::arch::arm64::ID_REG_YMM3:
            std::get<0>(ret) = "ymm3";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM3;
            break;

          case triton::arch::arm64::ID_REG_YMM4:
            std::get<0>(ret) = "ymm4";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM4;
            break;

          case triton::arch::arm64::ID_REG_YMM5:
            std::get<0>(ret) = "ymm5";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM5;
            break;

          case triton::arch::arm64::ID_REG_YMM6:
            std::get<0>(ret) = "ymm6";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM6;
            break;

          case triton::arch::arm64::ID_REG_YMM7:
            std::get<0>(ret) = "ymm7";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM7;
            break;

          case triton::arch::arm64::ID_REG_YMM8:
            std::get<0>(ret) = "ymm8";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM8;
            break;

          case triton::arch::arm64::ID_REG_YMM9:
            std::get<0>(ret) = "ymm9";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM9;
            break;

          case triton::arch::arm64::ID_REG_YMM10:
            std::get<0>(ret) = "ymm10";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM10;
            break;

          case triton::arch::arm64::ID_REG_YMM11:
            std::get<0>(ret) = "ymm11";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM11;
            break;

          case triton::arch::arm64::ID_REG_YMM12:
            std::get<0>(ret) = "ymm12";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM12;
            break;

          case triton::arch::arm64::ID_REG_YMM13:
            std::get<0>(ret) = "ymm13";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM13;
            break;

          case triton::arch::arm64::ID_REG_YMM14:
            std::get<0>(ret) = "ymm14";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM14;
            break;

          case triton::arch::arm64::ID_REG_YMM15:
            std::get<0>(ret) = "ymm15";
            std::get<1>(ret) = QQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_YMM15;
            break;

          case triton::arch::arm64::ID_REG_ZMM0:
            std::get<0>(ret) = "zmm0";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM0;
            break;

          case triton::arch::arm64::ID_REG_ZMM1:
            std::get<0>(ret) = "zmm1";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM1;
            break;

          case triton::arch::arm64::ID_REG_ZMM2:
            std::get<0>(ret) = "zmm2";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM2;
            break;

          case triton::arch::arm64::ID_REG_ZMM3:
            std::get<0>(ret) = "zmm3";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM3;
            break;

          case triton::arch::arm64::ID_REG_ZMM4:
            std::get<0>(ret) = "zmm4";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM4;
            break;

          case triton::arch::arm64::ID_REG_ZMM5:
            std::get<0>(ret) = "zmm5";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM5;
            break;

          case triton::arch::arm64::ID_REG_ZMM6:
            std::get<0>(ret) = "zmm6";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM6;
            break;

          case triton::arch::arm64::ID_REG_ZMM7:
            std::get<0>(ret) = "zmm7";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM7;
            break;

          case triton::arch::arm64::ID_REG_ZMM8:
            std::get<0>(ret) = "zmm8";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM8;
            break;

          case triton::arch::arm64::ID_REG_ZMM9:
            std::get<0>(ret) = "zmm9";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM9;
            break;

          case triton::arch::arm64::ID_REG_ZMM10:
            std::get<0>(ret) = "zmm10";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM10;
            break;

          case triton::arch::arm64::ID_REG_ZMM11:
            std::get<0>(ret) = "zmm11";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM11;
            break;

          case triton::arch::arm64::ID_REG_ZMM12:
            std::get<0>(ret) = "zmm12";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM12;
            break;

          case triton::arch::arm64::ID_REG_ZMM13:
            std::get<0>(ret) = "zmm13";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM13;
            break;

          case triton::arch::arm64::ID_REG_ZMM14:
            std::get<0>(ret) = "zmm14";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM14;
            break;

          case triton::arch::arm64::ID_REG_ZMM15:
            std::get<0>(ret) = "zmm15";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM15;
            break;

          case triton::arch::arm64::ID_REG_ZMM16:
            std::get<0>(ret) = "zmm16";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM16;
            break;

          case triton::arch::arm64::ID_REG_ZMM17:
            std::get<0>(ret) = "zmm17";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM17;
            break;

          case triton::arch::arm64::ID_REG_ZMM18:
            std::get<0>(ret) = "zmm18";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM18;
            break;

          case triton::arch::arm64::ID_REG_ZMM19:
            std::get<0>(ret) = "zmm19";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM19;
            break;

          case triton::arch::arm64::ID_REG_ZMM20:
            std::get<0>(ret) = "zmm20";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM20;
            break;

          case triton::arch::arm64::ID_REG_ZMM21:
            std::get<0>(ret) = "zmm21";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM21;
            break;

          case triton::arch::arm64::ID_REG_ZMM22:
            std::get<0>(ret) = "zmm22";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM22;
            break;

          case triton::arch::arm64::ID_REG_ZMM23:
            std::get<0>(ret) = "zmm23";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM23;
            break;

          case triton::arch::arm64::ID_REG_ZMM24:
            std::get<0>(ret) = "zmm24";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM24;
            break;

          case triton::arch::arm64::ID_REG_ZMM25:
            std::get<0>(ret) = "zmm25";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM25;
            break;

          case triton::arch::arm64::ID_REG_ZMM26:
            std::get<0>(ret) = "zmm26";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM26;
            break;

          case triton::arch::arm64::ID_REG_ZMM27:
            std::get<0>(ret) = "zmm27";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM27;
            break;

          case triton::arch::arm64::ID_REG_ZMM28:
            std::get<0>(ret) = "zmm28";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM28;
            break;

          case triton::arch::arm64::ID_REG_ZMM29:
            std::get<0>(ret) = "zmm29";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM29;
            break;

          case triton::arch::arm64::ID_REG_ZMM30:
            std::get<0>(ret) = "zmm30";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM30;
            break;

          case triton::arch::arm64::ID_REG_ZMM31:
            std::get<0>(ret) = "zmm31";
            std::get<1>(ret) = DQQWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZMM31;
            break;

          case triton::arch::arm64::ID_REG_MXCSR:
            std::get<0>(ret) = "mxcsr";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_MXCSR;
            break;

          case triton::arch::arm64::ID_REG_CR0:
            std::get<0>(ret) = "cr0";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR0;
            break;

          case triton::arch::arm64::ID_REG_CR1:
            std::get<0>(ret) = "cr1";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR1;
            break;

          case triton::arch::arm64::ID_REG_CR2:
            std::get<0>(ret) = "cr2";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR2;
            break;

          case triton::arch::arm64::ID_REG_CR3:
            std::get<0>(ret) = "cr3";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR3;
            break;

          case triton::arch::arm64::ID_REG_CR4:
            std::get<0>(ret) = "cr4";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR4;
            break;

          case triton::arch::arm64::ID_REG_CR5:
            std::get<0>(ret) = "cr5";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR5;
            break;

          case triton::arch::arm64::ID_REG_CR6:
            std::get<0>(ret) = "cr6";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR6;
            break;

          case triton::arch::arm64::ID_REG_CR7:
            std::get<0>(ret) = "cr7";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR7;
            break;

          case triton::arch::arm64::ID_REG_CR8:
            std::get<0>(ret) = "cr8";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR8;
            break;

          case triton::arch::arm64::ID_REG_CR9:
            std::get<0>(ret) = "cr9";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR9;
            break;

          case triton::arch::arm64::ID_REG_CR10:
            std::get<0>(ret) = "cr10";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR10;
            break;

          case triton::arch::arm64::ID_REG_CR11:
            std::get<0>(ret) = "cr11";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR11;
            break;

          case triton::arch::arm64::ID_REG_CR12:
            std::get<0>(ret) = "cr12";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR12;
            break;

          case triton::arch::arm64::ID_REG_CR13:
            std::get<0>(ret) = "cr13";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR13;
            break;

          case triton::arch::arm64::ID_REG_CR14:
            std::get<0>(ret) = "cr14";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR14;
            break;

          case triton::arch::arm64::ID_REG_CR15:
            std::get<0>(ret) = "cr15";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CR15;
            break;

          case triton::arch::arm64::ID_REG_IE:
            std::get<0>(ret) = "ie";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_IE;
            break;

          case triton::arch::arm64::ID_REG_DE:
            std::get<0>(ret) = "de";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_DE;
            break;

          case triton::arch::arm64::ID_REG_ZE:
            std::get<0>(ret) = "ze";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZE;
            break;

          case triton::arch::arm64::ID_REG_OE:
            std::get<0>(ret) = "oe";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_OE;
            break;

          case triton::arch::arm64::ID_REG_UE:
            std::get<0>(ret) = "ue";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_UE;
            break;

          case triton::arch::arm64::ID_REG_PE:
            std::get<0>(ret) = "pe";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_PE;
            break;

          case triton::arch::arm64::ID_REG_DAZ:
            std::get<0>(ret) = "da";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_DAZ;
            break;

          case triton::arch::arm64::ID_REG_IM:
            std::get<0>(ret) = "im";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_IM;
            break;

          case triton::arch::arm64::ID_REG_DM:
            std::get<0>(ret) = "dm";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_DM;
            break;

          case triton::arch::arm64::ID_REG_ZM:
            std::get<0>(ret) = "zm";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZM;
            break;

          case triton::arch::arm64::ID_REG_OM:
            std::get<0>(ret) = "om";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_OM;
            break;

          case triton::arch::arm64::ID_REG_UM:
            std::get<0>(ret) = "um";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_UM;
            break;

          case triton::arch::arm64::ID_REG_PM:
            std::get<0>(ret) = "pm";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_PM;
            break;

          case triton::arch::arm64::ID_REG_RL:
            std::get<0>(ret) = "rl";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RL;
            break;

          case triton::arch::arm64::ID_REG_RH:
            std::get<0>(ret) = "rh";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_RH;
            break;

          case triton::arch::arm64::ID_REG_FZ:
            std::get<0>(ret) = "fz";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_FZ;
            break;

          case triton::arch::arm64::ID_REG_AF:
            std::get<0>(ret) = "af";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_AF;
            break;

          case triton::arch::arm64::ID_REG_CF:
            std::get<0>(ret) = "cf";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CF;
            break;

          case triton::arch::arm64::ID_REG_DF:
            std::get<0>(ret) = "df";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_DF;
            break;

          case triton::arch::arm64::ID_REG_IF:
            std::get<0>(ret) = "if";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_IF;
            break;

          case triton::arch::arm64::ID_REG_OF:
            std::get<0>(ret) = "of";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_OF;
            break;

          case triton::arch::arm64::ID_REG_PF:
            std::get<0>(ret) = "pf";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_PF;
            break;

          case triton::arch::arm64::ID_REG_SF:
            std::get<0>(ret) = "sf";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_SF;
            break;

          case triton::arch::arm64::ID_REG_TF:
            std::get<0>(ret) = "tf";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_TF;
            break;

          case triton::arch::arm64::ID_REG_ZF:
            std::get<0>(ret) = "zf";
            std::get<1>(ret) = 0;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ZF;
            break;

          case triton::arch::arm64::ID_REG_CS:
            std::get<0>(ret) = "cs";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_CS;
            break;

          case triton::arch::arm64::ID_REG_DS:
            std::get<0>(ret) = "ds";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_DS;
            break;

          case triton::arch::arm64::ID_REG_ES:
            std::get<0>(ret) = "es";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_ES;
            break;

          case triton::arch::arm64::ID_REG_FS:
            std::get<0>(ret) = "fs";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_FS;
            break;

          case triton::arch::arm64::ID_REG_GS:
            std::get<0>(ret) = "gs";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_GS;
            break;

          case triton::arch::arm64::ID_REG_SS:
            std::get<0>(ret) = "ss";
            std::get<1>(ret) = (triton::api.getArchitecture() == triton::arch::ARCH_ARM64_64) ? QWORD_SIZE_BIT-1 : DWORD_SIZE_BIT-1;
            std::get<2>(ret) = 0;
            std::get<3>(ret) = triton::arch::arm64::ID_REG_SS;
            break;

        }
        return ret;
      }


      /* Converts a capstone's register id to a triton's register id */
      triton::uint32 capstoneRegisterToTritonRegister(triton::uint32 id) {
        triton::uint32 tritonId = triton::arch::arm64::ID_REG_INVALID;

        if (triton::api.getArchitecture() == triton::arch::ARCH_INVALID)
          return tritonId;

        switch (id) {

          case triton::extlibs::capstone::ARM64_REG_RAX:
            tritonId = triton::arch::arm64::ID_REG_RAX;
            break;

          case triton::extlibs::capstone::ARM64_REG_EAX:
            tritonId = triton::arch::arm64::ID_REG_EAX;
            break;

          case triton::extlibs::capstone::ARM64_REG_AX:
            tritonId = triton::arch::arm64::ID_REG_AX;
            break;

          case triton::extlibs::capstone::ARM64_REG_AH:
            tritonId = triton::arch::arm64::ID_REG_AH;
            break;

          case triton::extlibs::capstone::ARM64_REG_AL:
            tritonId = triton::arch::arm64::ID_REG_AL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RBX:
            tritonId = triton::arch::arm64::ID_REG_RBX;
            break;

          case triton::extlibs::capstone::ARM64_REG_EBX:
            tritonId = triton::arch::arm64::ID_REG_EBX;
            break;

          case triton::extlibs::capstone::ARM64_REG_BX:
            tritonId = triton::arch::arm64::ID_REG_BX;
            break;

          case triton::extlibs::capstone::ARM64_REG_BH:
            tritonId = triton::arch::arm64::ID_REG_BH;
            break;

          case triton::extlibs::capstone::ARM64_REG_BL:
            tritonId = triton::arch::arm64::ID_REG_BL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RCX:
            tritonId = triton::arch::arm64::ID_REG_RCX;
            break;

          case triton::extlibs::capstone::ARM64_REG_ECX:
            tritonId = triton::arch::arm64::ID_REG_ECX;
            break;

          case triton::extlibs::capstone::ARM64_REG_CX:
            tritonId = triton::arch::arm64::ID_REG_CX;
            break;

          case triton::extlibs::capstone::ARM64_REG_CH:
            tritonId = triton::arch::arm64::ID_REG_CH;
            break;

          case triton::extlibs::capstone::ARM64_REG_CL:
            tritonId = triton::arch::arm64::ID_REG_CL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RDX:
            tritonId = triton::arch::arm64::ID_REG_RDX;
            break;

          case triton::extlibs::capstone::ARM64_REG_EDX:
            tritonId = triton::arch::arm64::ID_REG_EDX;
            break;

          case triton::extlibs::capstone::ARM64_REG_DX:
            tritonId = triton::arch::arm64::ID_REG_DX;
            break;

          case triton::extlibs::capstone::ARM64_REG_DH:
            tritonId = triton::arch::arm64::ID_REG_DH;
            break;

          case triton::extlibs::capstone::ARM64_REG_DL:
            tritonId = triton::arch::arm64::ID_REG_DL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RDI:
            tritonId = triton::arch::arm64::ID_REG_RDI;
            break;

          case triton::extlibs::capstone::ARM64_REG_EDI:
            tritonId = triton::arch::arm64::ID_REG_EDI;
            break;

          case triton::extlibs::capstone::ARM64_REG_DI:
            tritonId = triton::arch::arm64::ID_REG_DI;
            break;

          case triton::extlibs::capstone::ARM64_REG_DIL:
            tritonId = triton::arch::arm64::ID_REG_DIL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RSI:
            tritonId = triton::arch::arm64::ID_REG_RSI;
            break;

          case triton::extlibs::capstone::ARM64_REG_ESI:
            tritonId = triton::arch::arm64::ID_REG_ESI;
            break;

          case triton::extlibs::capstone::ARM64_REG_SI:
            tritonId = triton::arch::arm64::ID_REG_SI;
            break;

          case triton::extlibs::capstone::ARM64_REG_SIL:
            tritonId = triton::arch::arm64::ID_REG_SIL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RBP:
            tritonId = triton::arch::arm64::ID_REG_RBP;
            break;

          case triton::extlibs::capstone::ARM64_REG_EBP:
            tritonId = triton::arch::arm64::ID_REG_EBP;
            break;

          case triton::extlibs::capstone::ARM64_REG_BP:
            tritonId = triton::arch::arm64::ID_REG_BP;
            break;

          case triton::extlibs::capstone::ARM64_REG_BPL:
            tritonId = triton::arch::arm64::ID_REG_BPL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RSP:
            tritonId = triton::arch::arm64::ID_REG_RSP;
            break;

          case triton::extlibs::capstone::ARM64_REG_ESP:
            tritonId = triton::arch::arm64::ID_REG_ESP;
            break;

          case triton::extlibs::capstone::ARM64_REG_SP:
            tritonId = triton::arch::arm64::ID_REG_SP;
            break;

          case triton::extlibs::capstone::ARM64_REG_SPL:
            tritonId = triton::arch::arm64::ID_REG_SPL;
            break;

          case triton::extlibs::capstone::ARM64_REG_RIP:
            tritonId = triton::arch::arm64::ID_REG_RIP;
            break;

          case triton::extlibs::capstone::ARM64_REG_EIP:
            tritonId = triton::arch::arm64::ID_REG_EIP;
            break;

          case triton::extlibs::capstone::ARM64_REG_IP:
            tritonId = triton::arch::arm64::ID_REG_IP;
            break;

          case triton::extlibs::capstone::ARM64_REG_EFLAGS:
            tritonId = triton::arch::arm64::ID_REG_EFLAGS;
            break;

          case triton::extlibs::capstone::ARM64_REG_R8:
            tritonId = triton::arch::arm64::ID_REG_R8;
            break;

          case triton::extlibs::capstone::ARM64_REG_R8D:
            tritonId = triton::arch::arm64::ID_REG_R8D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R8W:
            tritonId = triton::arch::arm64::ID_REG_R8W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R8B:
            tritonId = triton::arch::arm64::ID_REG_R8B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R9:
            tritonId = triton::arch::arm64::ID_REG_R9;
            break;

          case triton::extlibs::capstone::ARM64_REG_R9D:
            tritonId = triton::arch::arm64::ID_REG_R9D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R9W:
            tritonId = triton::arch::arm64::ID_REG_R9W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R9B:
            tritonId = triton::arch::arm64::ID_REG_R9B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R10:
            tritonId = triton::arch::arm64::ID_REG_R10;
            break;

          case triton::extlibs::capstone::ARM64_REG_R10D:
            tritonId = triton::arch::arm64::ID_REG_R10D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R10W:
            tritonId = triton::arch::arm64::ID_REG_R10W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R10B:
            tritonId = triton::arch::arm64::ID_REG_R10B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R11:
            tritonId = triton::arch::arm64::ID_REG_R11;
            break;

          case triton::extlibs::capstone::ARM64_REG_R11D:
            tritonId = triton::arch::arm64::ID_REG_R11D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R11W:
            tritonId = triton::arch::arm64::ID_REG_R11W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R11B:
            tritonId = triton::arch::arm64::ID_REG_R11B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R12:
            tritonId = triton::arch::arm64::ID_REG_R12;
            break;

          case triton::extlibs::capstone::ARM64_REG_R12D:
            tritonId = triton::arch::arm64::ID_REG_R12D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R12W:
            tritonId = triton::arch::arm64::ID_REG_R12W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R12B:
            tritonId = triton::arch::arm64::ID_REG_R12B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R13:
            tritonId = triton::arch::arm64::ID_REG_R13;
            break;

          case triton::extlibs::capstone::ARM64_REG_R13D:
            tritonId = triton::arch::arm64::ID_REG_R13D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R13W:
            tritonId = triton::arch::arm64::ID_REG_R13W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R13B:
            tritonId = triton::arch::arm64::ID_REG_R13B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R14:
            tritonId = triton::arch::arm64::ID_REG_R14;
            break;

          case triton::extlibs::capstone::ARM64_REG_R14D:
            tritonId = triton::arch::arm64::ID_REG_R14D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R14W:
            tritonId = triton::arch::arm64::ID_REG_R14W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R14B:
            tritonId = triton::arch::arm64::ID_REG_R14B;
            break;

          case triton::extlibs::capstone::ARM64_REG_R15:
            tritonId = triton::arch::arm64::ID_REG_R15;
            break;

          case triton::extlibs::capstone::ARM64_REG_R15D:
            tritonId = triton::arch::arm64::ID_REG_R15D;
            break;

          case triton::extlibs::capstone::ARM64_REG_R15W:
            tritonId = triton::arch::arm64::ID_REG_R15W;
            break;

          case triton::extlibs::capstone::ARM64_REG_R15B:
            tritonId = triton::arch::arm64::ID_REG_R15B;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM0:
            tritonId = triton::arch::arm64::ID_REG_MM0;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM1:
            tritonId = triton::arch::arm64::ID_REG_MM1;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM2:
            tritonId = triton::arch::arm64::ID_REG_MM2;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM3:
            tritonId = triton::arch::arm64::ID_REG_MM3;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM4:
            tritonId = triton::arch::arm64::ID_REG_MM4;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM5:
            tritonId = triton::arch::arm64::ID_REG_MM5;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM6:
            tritonId = triton::arch::arm64::ID_REG_MM6;
            break;

          case triton::extlibs::capstone::ARM64_REG_MM7:
            tritonId = triton::arch::arm64::ID_REG_MM7;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM0:
            tritonId = triton::arch::arm64::ID_REG_XMM0;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM1:
            tritonId = triton::arch::arm64::ID_REG_XMM1;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM2:
            tritonId = triton::arch::arm64::ID_REG_XMM2;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM3:
            tritonId = triton::arch::arm64::ID_REG_XMM3;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM4:
            tritonId = triton::arch::arm64::ID_REG_XMM4;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM5:
            tritonId = triton::arch::arm64::ID_REG_XMM5;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM6:
            tritonId = triton::arch::arm64::ID_REG_XMM6;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM7:
            tritonId = triton::arch::arm64::ID_REG_XMM7;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM8:
            tritonId = triton::arch::arm64::ID_REG_XMM8;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM9:
            tritonId = triton::arch::arm64::ID_REG_XMM9;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM10:
            tritonId = triton::arch::arm64::ID_REG_XMM10;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM11:
            tritonId = triton::arch::arm64::ID_REG_XMM11;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM12:
            tritonId = triton::arch::arm64::ID_REG_XMM12;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM13:
            tritonId = triton::arch::arm64::ID_REG_XMM13;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM14:
            tritonId = triton::arch::arm64::ID_REG_XMM14;
            break;

          case triton::extlibs::capstone::ARM64_REG_XMM15:
            tritonId = triton::arch::arm64::ID_REG_XMM15;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM0:
            tritonId = triton::arch::arm64::ID_REG_YMM0;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM1:
            tritonId = triton::arch::arm64::ID_REG_YMM1;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM2:
            tritonId = triton::arch::arm64::ID_REG_YMM2;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM3:
            tritonId = triton::arch::arm64::ID_REG_YMM3;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM4:
            tritonId = triton::arch::arm64::ID_REG_YMM4;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM5:
            tritonId = triton::arch::arm64::ID_REG_YMM5;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM6:
            tritonId = triton::arch::arm64::ID_REG_YMM6;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM7:
            tritonId = triton::arch::arm64::ID_REG_YMM7;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM8:
            tritonId = triton::arch::arm64::ID_REG_YMM8;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM9:
            tritonId = triton::arch::arm64::ID_REG_YMM9;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM10:
            tritonId = triton::arch::arm64::ID_REG_YMM10;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM11:
            tritonId = triton::arch::arm64::ID_REG_YMM11;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM12:
            tritonId = triton::arch::arm64::ID_REG_YMM12;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM13:
            tritonId = triton::arch::arm64::ID_REG_YMM13;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM14:
            tritonId = triton::arch::arm64::ID_REG_YMM14;
            break;

          case triton::extlibs::capstone::ARM64_REG_YMM15:
            tritonId = triton::arch::arm64::ID_REG_YMM15;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM0:
            tritonId = triton::arch::arm64::ID_REG_ZMM0;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM1:
            tritonId = triton::arch::arm64::ID_REG_ZMM1;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM2:
            tritonId = triton::arch::arm64::ID_REG_ZMM2;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM3:
            tritonId = triton::arch::arm64::ID_REG_ZMM3;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM4:
            tritonId = triton::arch::arm64::ID_REG_ZMM4;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM5:
            tritonId = triton::arch::arm64::ID_REG_ZMM5;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM6:
            tritonId = triton::arch::arm64::ID_REG_ZMM6;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM7:
            tritonId = triton::arch::arm64::ID_REG_ZMM7;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM8:
            tritonId = triton::arch::arm64::ID_REG_ZMM8;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM9:
            tritonId = triton::arch::arm64::ID_REG_ZMM9;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM10:
            tritonId = triton::arch::arm64::ID_REG_ZMM10;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM11:
            tritonId = triton::arch::arm64::ID_REG_ZMM11;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM12:
            tritonId = triton::arch::arm64::ID_REG_ZMM12;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM13:
            tritonId = triton::arch::arm64::ID_REG_ZMM13;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM14:
            tritonId = triton::arch::arm64::ID_REG_ZMM14;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM15:
            tritonId = triton::arch::arm64::ID_REG_ZMM15;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM16:
            tritonId = triton::arch::arm64::ID_REG_ZMM16;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM17:
            tritonId = triton::arch::arm64::ID_REG_ZMM17;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM18:
            tritonId = triton::arch::arm64::ID_REG_ZMM18;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM19:
            tritonId = triton::arch::arm64::ID_REG_ZMM19;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM20:
            tritonId = triton::arch::arm64::ID_REG_ZMM20;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM21:
            tritonId = triton::arch::arm64::ID_REG_ZMM21;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM22:
            tritonId = triton::arch::arm64::ID_REG_ZMM22;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM23:
            tritonId = triton::arch::arm64::ID_REG_ZMM23;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM24:
            tritonId = triton::arch::arm64::ID_REG_ZMM24;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM25:
            tritonId = triton::arch::arm64::ID_REG_ZMM25;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM26:
            tritonId = triton::arch::arm64::ID_REG_ZMM26;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM27:
            tritonId = triton::arch::arm64::ID_REG_ZMM27;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM28:
            tritonId = triton::arch::arm64::ID_REG_ZMM28;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM29:
            tritonId = triton::arch::arm64::ID_REG_ZMM29;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM30:
            tritonId = triton::arch::arm64::ID_REG_ZMM30;
            break;

          case triton::extlibs::capstone::ARM64_REG_ZMM31:
            tritonId = triton::arch::arm64::ID_REG_ZMM31;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR0:
            tritonId = triton::arch::arm64::ID_REG_CR0;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR1:
            tritonId = triton::arch::arm64::ID_REG_CR1;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR2:
            tritonId = triton::arch::arm64::ID_REG_CR2;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR3:
            tritonId = triton::arch::arm64::ID_REG_CR3;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR4:
            tritonId = triton::arch::arm64::ID_REG_CR4;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR5:
            tritonId = triton::arch::arm64::ID_REG_CR5;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR6:
            tritonId = triton::arch::arm64::ID_REG_CR6;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR7:
            tritonId = triton::arch::arm64::ID_REG_CR7;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR8:
            tritonId = triton::arch::arm64::ID_REG_CR8;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR9:
            tritonId = triton::arch::arm64::ID_REG_CR9;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR10:
            tritonId = triton::arch::arm64::ID_REG_CR10;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR11:
            tritonId = triton::arch::arm64::ID_REG_CR11;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR12:
            tritonId = triton::arch::arm64::ID_REG_CR12;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR13:
            tritonId = triton::arch::arm64::ID_REG_CR13;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR14:
            tritonId = triton::arch::arm64::ID_REG_CR14;
            break;

          case triton::extlibs::capstone::ARM64_REG_CR15:
            tritonId = triton::arch::arm64::ID_REG_CR15;
            break;

          case triton::extlibs::capstone::ARM64_REG_CS:
            tritonId = triton::arch::arm64::ID_REG_CS;
            break;

          case triton::extlibs::capstone::ARM64_REG_DS:
            tritonId = triton::arch::arm64::ID_REG_DS;
            break;

          case triton::extlibs::capstone::ARM64_REG_ES:
            tritonId = triton::arch::arm64::ID_REG_ES;
            break;

          case triton::extlibs::capstone::ARM64_REG_FS:
            tritonId = triton::arch::arm64::ID_REG_FS;
            break;

          case triton::extlibs::capstone::ARM64_REG_GS:
            tritonId = triton::arch::arm64::ID_REG_GS;
            break;

          case triton::extlibs::capstone::ARM64_REG_SS:
            tritonId = triton::arch::arm64::ID_REG_SS;
            break;

          default:
            tritonId = triton::arch::arm64::ID_REG_INVALID;
            break;

        }
        return tritonId;
      }


      /* Converts a capstone's instruction id to a triton's instruction id */
      triton::uint32 capstoneInstructionToTritonInstruction(triton::uint32 id) {
        triton::uint32 tritonId = triton::arch::arm64::ID_INST_INVALID;

        if (triton::api.getArchitecture() == triton::arch::ARCH_INVALID)
          return tritonId;

        switch (id) {

          case triton::extlibs::capstone::ARM64_INS_INVALID:
            tritonId = triton::arch::arm64::ID_INST_INVALID;
            break;

          case triton::extlibs::capstone::ARM64_INS_AAA:
            tritonId = triton::arch::arm64::ID_INS_AAA;
            break;

          case triton::extlibs::capstone::ARM64_INS_AAD:
            tritonId = triton::arch::arm64::ID_INS_AAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_AAM:
            tritonId = triton::arch::arm64::ID_INS_AAM;
            break;

          case triton::extlibs::capstone::ARM64_INS_AAS:
            tritonId = triton::arch::arm64::ID_INS_AAS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FABS:
            tritonId = triton::arch::arm64::ID_INS_FABS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADC:
            tritonId = triton::arch::arm64::ID_INS_ADC;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADCX:
            tritonId = triton::arch::arm64::ID_INS_ADCX;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADD:
            tritonId = triton::arch::arm64::ID_INS_ADD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDPD:
            tritonId = triton::arch::arm64::ID_INS_ADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDPS:
            tritonId = triton::arch::arm64::ID_INS_ADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDSD:
            tritonId = triton::arch::arm64::ID_INS_ADDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDSS:
            tritonId = triton::arch::arm64::ID_INS_ADDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDSUBPD:
            tritonId = triton::arch::arm64::ID_INS_ADDSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADDSUBPS:
            tritonId = triton::arch::arm64::ID_INS_ADDSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FADD:
            tritonId = triton::arch::arm64::ID_INS_FADD;
            break;

          case triton::extlibs::capstone::ARM64_INS_FIADD:
            tritonId = triton::arch::arm64::ID_INS_FIADD;
            break;

          case triton::extlibs::capstone::ARM64_INS_FADDP:
            tritonId = triton::arch::arm64::ID_INS_FADDP;
            break;

          case triton::extlibs::capstone::ARM64_INS_ADOX:
            tritonId = triton::arch::arm64::ID_INS_ADOX;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESDECLAST:
            tritonId = triton::arch::arm64::ID_INS_AESDECLAST;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESDEC:
            tritonId = triton::arch::arm64::ID_INS_AESDEC;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESENCLAST:
            tritonId = triton::arch::arm64::ID_INS_AESENCLAST;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESENC:
            tritonId = triton::arch::arm64::ID_INS_AESENC;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESIMC:
            tritonId = triton::arch::arm64::ID_INS_AESIMC;
            break;

          case triton::extlibs::capstone::ARM64_INS_AESKEYGENASSIST:
            tritonId = triton::arch::arm64::ID_INS_AESKEYGENASSIST;
            break;

          case triton::extlibs::capstone::ARM64_INS_AND:
            tritonId = triton::arch::arm64::ID_INS_AND;
            break;

          case triton::extlibs::capstone::ARM64_INS_ANDN:
            tritonId = triton::arch::arm64::ID_INS_ANDN;
            break;

          case triton::extlibs::capstone::ARM64_INS_ANDNPD:
            tritonId = triton::arch::arm64::ID_INS_ANDNPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ANDNPS:
            tritonId = triton::arch::arm64::ID_INS_ANDNPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ANDPD:
            tritonId = triton::arch::arm64::ID_INS_ANDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ANDPS:
            tritonId = triton::arch::arm64::ID_INS_ANDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ARPL:
            tritonId = triton::arch::arm64::ID_INS_ARPL;
            break;

          case triton::extlibs::capstone::ARM64_INS_BEXTR:
            tritonId = triton::arch::arm64::ID_INS_BEXTR;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLCFILL:
            tritonId = triton::arch::arm64::ID_INS_BLCFILL;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLCI:
            tritonId = triton::arch::arm64::ID_INS_BLCI;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLCIC:
            tritonId = triton::arch::arm64::ID_INS_BLCIC;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLCMSK:
            tritonId = triton::arch::arm64::ID_INS_BLCMSK;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLCS:
            tritonId = triton::arch::arm64::ID_INS_BLCS;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLENDPD:
            tritonId = triton::arch::arm64::ID_INS_BLENDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLENDPS:
            tritonId = triton::arch::arm64::ID_INS_BLENDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLENDVPD:
            tritonId = triton::arch::arm64::ID_INS_BLENDVPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLENDVPS:
            tritonId = triton::arch::arm64::ID_INS_BLENDVPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLSFILL:
            tritonId = triton::arch::arm64::ID_INS_BLSFILL;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLSI:
            tritonId = triton::arch::arm64::ID_INS_BLSI;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLSIC:
            tritonId = triton::arch::arm64::ID_INS_BLSIC;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLSMSK:
            tritonId = triton::arch::arm64::ID_INS_BLSMSK;
            break;

          case triton::extlibs::capstone::ARM64_INS_BLSR:
            tritonId = triton::arch::arm64::ID_INS_BLSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_BOUND:
            tritonId = triton::arch::arm64::ID_INS_BOUND;
            break;

          case triton::extlibs::capstone::ARM64_INS_BSF:
            tritonId = triton::arch::arm64::ID_INS_BSF;
            break;

          case triton::extlibs::capstone::ARM64_INS_BSR:
            tritonId = triton::arch::arm64::ID_INS_BSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_BSWAP:
            tritonId = triton::arch::arm64::ID_INS_BSWAP;
            break;

          case triton::extlibs::capstone::ARM64_INS_BT:
            tritonId = triton::arch::arm64::ID_INS_BT;
            break;

          case triton::extlibs::capstone::ARM64_INS_BTC:
            tritonId = triton::arch::arm64::ID_INS_BTC;
            break;

          case triton::extlibs::capstone::ARM64_INS_BTR:
            tritonId = triton::arch::arm64::ID_INS_BTR;
            break;

          case triton::extlibs::capstone::ARM64_INS_BTS:
            tritonId = triton::arch::arm64::ID_INS_BTS;
            break;

          case triton::extlibs::capstone::ARM64_INS_BZHI:
            tritonId = triton::arch::arm64::ID_INS_BZHI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CALL:
            tritonId = triton::arch::arm64::ID_INS_CALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_CBW:
            tritonId = triton::arch::arm64::ID_INS_CBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_CDQ:
            tritonId = triton::arch::arm64::ID_INS_CDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CDQE:
            tritonId = triton::arch::arm64::ID_INS_CDQE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCHS:
            tritonId = triton::arch::arm64::ID_INS_FCHS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLAC:
            tritonId = triton::arch::arm64::ID_INS_CLAC;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLC:
            tritonId = triton::arch::arm64::ID_INS_CLC;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLD:
            tritonId = triton::arch::arm64::ID_INS_CLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLFLUSH:
            tritonId = triton::arch::arm64::ID_INS_CLFLUSH;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLGI:
            tritonId = triton::arch::arm64::ID_INS_CLGI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLI:
            tritonId = triton::arch::arm64::ID_INS_CLI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CLTS:
            tritonId = triton::arch::arm64::ID_INS_CLTS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMC:
            tritonId = triton::arch::arm64::ID_INS_CMC;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVA:
            tritonId = triton::arch::arm64::ID_INS_CMOVA;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVAE:
            tritonId = triton::arch::arm64::ID_INS_CMOVAE;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVB:
            tritonId = triton::arch::arm64::ID_INS_CMOVB;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVBE:
            tritonId = triton::arch::arm64::ID_INS_CMOVBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVBE:
            tritonId = triton::arch::arm64::ID_INS_FCMOVBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVB:
            tritonId = triton::arch::arm64::ID_INS_FCMOVB;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVE:
            tritonId = triton::arch::arm64::ID_INS_CMOVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVE:
            tritonId = triton::arch::arm64::ID_INS_FCMOVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVG:
            tritonId = triton::arch::arm64::ID_INS_CMOVG;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVGE:
            tritonId = triton::arch::arm64::ID_INS_CMOVGE;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVL:
            tritonId = triton::arch::arm64::ID_INS_CMOVL;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVLE:
            tritonId = triton::arch::arm64::ID_INS_CMOVLE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVNBE:
            tritonId = triton::arch::arm64::ID_INS_FCMOVNBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVNB:
            tritonId = triton::arch::arm64::ID_INS_FCMOVNB;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVNE:
            tritonId = triton::arch::arm64::ID_INS_CMOVNE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVNE:
            tritonId = triton::arch::arm64::ID_INS_FCMOVNE;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVNO:
            tritonId = triton::arch::arm64::ID_INS_CMOVNO;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVNP:
            tritonId = triton::arch::arm64::ID_INS_CMOVNP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVNU:
            tritonId = triton::arch::arm64::ID_INS_FCMOVNU;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVNS:
            tritonId = triton::arch::arm64::ID_INS_CMOVNS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVO:
            tritonId = triton::arch::arm64::ID_INS_CMOVO;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVP:
            tritonId = triton::arch::arm64::ID_INS_CMOVP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCMOVU:
            tritonId = triton::arch::arm64::ID_INS_FCMOVU;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMOVS:
            tritonId = triton::arch::arm64::ID_INS_CMOVS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMP:
            tritonId = triton::arch::arm64::ID_INS_CMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPPD:
            tritonId = triton::arch::arm64::ID_INS_CMPPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPPS:
            tritonId = triton::arch::arm64::ID_INS_CMPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPSB:
            tritonId = triton::arch::arm64::ID_INS_CMPSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPSD:
            tritonId = triton::arch::arm64::ID_INS_CMPSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPSQ:
            tritonId = triton::arch::arm64::ID_INS_CMPSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPSS:
            tritonId = triton::arch::arm64::ID_INS_CMPSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPSW:
            tritonId = triton::arch::arm64::ID_INS_CMPSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPXCHG16B:
            tritonId = triton::arch::arm64::ID_INS_CMPXCHG16B;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPXCHG:
            tritonId = triton::arch::arm64::ID_INS_CMPXCHG;
            break;

          case triton::extlibs::capstone::ARM64_INS_CMPXCHG8B:
            tritonId = triton::arch::arm64::ID_INS_CMPXCHG8B;
            break;

          case triton::extlibs::capstone::ARM64_INS_COMISD:
            tritonId = triton::arch::arm64::ID_INS_COMISD;
            break;

          case triton::extlibs::capstone::ARM64_INS_COMISS:
            tritonId = triton::arch::arm64::ID_INS_COMISS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOMP:
            tritonId = triton::arch::arm64::ID_INS_FCOMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOMPI:
            tritonId = triton::arch::arm64::ID_INS_FCOMPI;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOMI:
            tritonId = triton::arch::arm64::ID_INS_FCOMI;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOM:
            tritonId = triton::arch::arm64::ID_INS_FCOM;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOS:
            tritonId = triton::arch::arm64::ID_INS_FCOS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CPUID:
            tritonId = triton::arch::arm64::ID_INS_CPUID;
            break;

          case triton::extlibs::capstone::ARM64_INS_CQO:
            tritonId = triton::arch::arm64::ID_INS_CQO;
            break;

          case triton::extlibs::capstone::ARM64_INS_CRC32:
            tritonId = triton::arch::arm64::ID_INS_CRC32;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTDQ2PD:
            tritonId = triton::arch::arm64::ID_INS_CVTDQ2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTDQ2PS:
            tritonId = triton::arch::arm64::ID_INS_CVTDQ2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPD2DQ:
            tritonId = triton::arch::arm64::ID_INS_CVTPD2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPD2PS:
            tritonId = triton::arch::arm64::ID_INS_CVTPD2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPS2DQ:
            tritonId = triton::arch::arm64::ID_INS_CVTPS2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPS2PD:
            tritonId = triton::arch::arm64::ID_INS_CVTPS2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSD2SI:
            tritonId = triton::arch::arm64::ID_INS_CVTSD2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSD2SS:
            tritonId = triton::arch::arm64::ID_INS_CVTSD2SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSI2SD:
            tritonId = triton::arch::arm64::ID_INS_CVTSI2SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSI2SS:
            tritonId = triton::arch::arm64::ID_INS_CVTSI2SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSS2SD:
            tritonId = triton::arch::arm64::ID_INS_CVTSS2SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTSS2SI:
            tritonId = triton::arch::arm64::ID_INS_CVTSS2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTPD2DQ:
            tritonId = triton::arch::arm64::ID_INS_CVTTPD2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTPS2DQ:
            tritonId = triton::arch::arm64::ID_INS_CVTTPS2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTSD2SI:
            tritonId = triton::arch::arm64::ID_INS_CVTTSD2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTSS2SI:
            tritonId = triton::arch::arm64::ID_INS_CVTTSS2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CWD:
            tritonId = triton::arch::arm64::ID_INS_CWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CWDE:
            tritonId = triton::arch::arm64::ID_INS_CWDE;
            break;

          case triton::extlibs::capstone::ARM64_INS_DAA:
            tritonId = triton::arch::arm64::ID_INS_DAA;
            break;

          case triton::extlibs::capstone::ARM64_INS_DAS:
            tritonId = triton::arch::arm64::ID_INS_DAS;
            break;

          case triton::extlibs::capstone::ARM64_INS_DATA16:
            tritonId = triton::arch::arm64::ID_INS_DATA16;
            break;

          case triton::extlibs::capstone::ARM64_INS_DEC:
            tritonId = triton::arch::arm64::ID_INS_DEC;
            break;

          case triton::extlibs::capstone::ARM64_INS_DIV:
            tritonId = triton::arch::arm64::ID_INS_DIV;
            break;

          case triton::extlibs::capstone::ARM64_INS_DIVPD:
            tritonId = triton::arch::arm64::ID_INS_DIVPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_DIVPS:
            tritonId = triton::arch::arm64::ID_INS_DIVPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FDIVR:
            tritonId = triton::arch::arm64::ID_INS_FDIVR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FIDIVR:
            tritonId = triton::arch::arm64::ID_INS_FIDIVR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FDIVRP:
            tritonId = triton::arch::arm64::ID_INS_FDIVRP;
            break;

          case triton::extlibs::capstone::ARM64_INS_DIVSD:
            tritonId = triton::arch::arm64::ID_INS_DIVSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_DIVSS:
            tritonId = triton::arch::arm64::ID_INS_DIVSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FDIV:
            tritonId = triton::arch::arm64::ID_INS_FDIV;
            break;

          case triton::extlibs::capstone::ARM64_INS_FIDIV:
            tritonId = triton::arch::arm64::ID_INS_FIDIV;
            break;

          case triton::extlibs::capstone::ARM64_INS_FDIVP:
            tritonId = triton::arch::arm64::ID_INS_FDIVP;
            break;

          case triton::extlibs::capstone::ARM64_INS_DPPD:
            tritonId = triton::arch::arm64::ID_INS_DPPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_DPPS:
            tritonId = triton::arch::arm64::ID_INS_DPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_RET:
            tritonId = triton::arch::arm64::ID_INS_RET;
            break;

          case triton::extlibs::capstone::ARM64_INS_ENCLS:
            tritonId = triton::arch::arm64::ID_INS_ENCLS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ENCLU:
            tritonId = triton::arch::arm64::ID_INS_ENCLU;
            break;

          case triton::extlibs::capstone::ARM64_INS_ENTER:
            tritonId = triton::arch::arm64::ID_INS_ENTER;
            break;

          case triton::extlibs::capstone::ARM64_INS_EXTRACTPS:
            tritonId = triton::arch::arm64::ID_INS_EXTRACTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_EXTRQ:
            tritonId = triton::arch::arm64::ID_INS_EXTRQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_F2XM1:
            tritonId = triton::arch::arm64::ID_INS_F2XM1;
            break;

          case triton::extlibs::capstone::ARM64_INS_LCALL:
            tritonId = triton::arch::arm64::ID_INS_LCALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_LJMP:
            tritonId = triton::arch::arm64::ID_INS_LJMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FBLD:
            tritonId = triton::arch::arm64::ID_INS_FBLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_FBSTP:
            tritonId = triton::arch::arm64::ID_INS_FBSTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FCOMPP:
            tritonId = triton::arch::arm64::ID_INS_FCOMPP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FDECSTP:
            tritonId = triton::arch::arm64::ID_INS_FDECSTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FEMMS:
            tritonId = triton::arch::arm64::ID_INS_FEMMS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FFREE:
            tritonId = triton::arch::arm64::ID_INS_FFREE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FICOM:
            tritonId = triton::arch::arm64::ID_INS_FICOM;
            break;

          case triton::extlibs::capstone::ARM64_INS_FICOMP:
            tritonId = triton::arch::arm64::ID_INS_FICOMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FINCSTP:
            tritonId = triton::arch::arm64::ID_INS_FINCSTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDCW:
            tritonId = triton::arch::arm64::ID_INS_FLDCW;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDENV:
            tritonId = triton::arch::arm64::ID_INS_FLDENV;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDL2E:
            tritonId = triton::arch::arm64::ID_INS_FLDL2E;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDL2T:
            tritonId = triton::arch::arm64::ID_INS_FLDL2T;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDLG2:
            tritonId = triton::arch::arm64::ID_INS_FLDLG2;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDLN2:
            tritonId = triton::arch::arm64::ID_INS_FLDLN2;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDPI:
            tritonId = triton::arch::arm64::ID_INS_FLDPI;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNCLEX:
            tritonId = triton::arch::arm64::ID_INS_FNCLEX;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNINIT:
            tritonId = triton::arch::arm64::ID_INS_FNINIT;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNOP:
            tritonId = triton::arch::arm64::ID_INS_FNOP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNSTCW:
            tritonId = triton::arch::arm64::ID_INS_FNSTCW;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNSTSW:
            tritonId = triton::arch::arm64::ID_INS_FNSTSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_FPATAN:
            tritonId = triton::arch::arm64::ID_INS_FPATAN;
            break;

          case triton::extlibs::capstone::ARM64_INS_FPREM:
            tritonId = triton::arch::arm64::ID_INS_FPREM;
            break;

          case triton::extlibs::capstone::ARM64_INS_FPREM1:
            tritonId = triton::arch::arm64::ID_INS_FPREM1;
            break;

          case triton::extlibs::capstone::ARM64_INS_FPTAN:
            tritonId = triton::arch::arm64::ID_INS_FPTAN;
            break;

          case triton::extlibs::capstone::ARM64_INS_FRNDINT:
            tritonId = triton::arch::arm64::ID_INS_FRNDINT;
            break;

          case triton::extlibs::capstone::ARM64_INS_FRSTOR:
            tritonId = triton::arch::arm64::ID_INS_FRSTOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNSAVE:
            tritonId = triton::arch::arm64::ID_INS_FNSAVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSCALE:
            tritonId = triton::arch::arm64::ID_INS_FSCALE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSETPM:
            tritonId = triton::arch::arm64::ID_INS_FSETPM;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSINCOS:
            tritonId = triton::arch::arm64::ID_INS_FSINCOS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FNSTENV:
            tritonId = triton::arch::arm64::ID_INS_FNSTENV;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXAM:
            tritonId = triton::arch::arm64::ID_INS_FXAM;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXRSTOR:
            tritonId = triton::arch::arm64::ID_INS_FXRSTOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXRSTOR64:
            tritonId = triton::arch::arm64::ID_INS_FXRSTOR64;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXSAVE:
            tritonId = triton::arch::arm64::ID_INS_FXSAVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXSAVE64:
            tritonId = triton::arch::arm64::ID_INS_FXSAVE64;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXTRACT:
            tritonId = triton::arch::arm64::ID_INS_FXTRACT;
            break;

          case triton::extlibs::capstone::ARM64_INS_FYL2X:
            tritonId = triton::arch::arm64::ID_INS_FYL2X;
            break;

          case triton::extlibs::capstone::ARM64_INS_FYL2XP1:
            tritonId = triton::arch::arm64::ID_INS_FYL2XP1;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVAPD:
            tritonId = triton::arch::arm64::ID_INS_MOVAPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVAPS:
            tritonId = triton::arch::arm64::ID_INS_MOVAPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ORPD:
            tritonId = triton::arch::arm64::ID_INS_ORPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ORPS:
            tritonId = triton::arch::arm64::ID_INS_ORPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVAPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVAPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVAPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVAPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_XORPD:
            tritonId = triton::arch::arm64::ID_INS_XORPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_XORPS:
            tritonId = triton::arch::arm64::ID_INS_XORPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_GETSEC:
            tritonId = triton::arch::arm64::ID_INS_GETSEC;
            break;

          case triton::extlibs::capstone::ARM64_INS_HADDPD:
            tritonId = triton::arch::arm64::ID_INS_HADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_HADDPS:
            tritonId = triton::arch::arm64::ID_INS_HADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_HLT:
            tritonId = triton::arch::arm64::ID_INS_HLT;
            break;

          case triton::extlibs::capstone::ARM64_INS_HSUBPD:
            tritonId = triton::arch::arm64::ID_INS_HSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_HSUBPS:
            tritonId = triton::arch::arm64::ID_INS_HSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_IDIV:
            tritonId = triton::arch::arm64::ID_INS_IDIV;
            break;

          case triton::extlibs::capstone::ARM64_INS_FILD:
            tritonId = triton::arch::arm64::ID_INS_FILD;
            break;

          case triton::extlibs::capstone::ARM64_INS_IMUL:
            tritonId = triton::arch::arm64::ID_INS_IMUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_IN:
            tritonId = triton::arch::arm64::ID_INS_IN;
            break;

          case triton::extlibs::capstone::ARM64_INS_INC:
            tritonId = triton::arch::arm64::ID_INS_INC;
            break;

          case triton::extlibs::capstone::ARM64_INS_INSB:
            tritonId = triton::arch::arm64::ID_INS_INSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_INSERTPS:
            tritonId = triton::arch::arm64::ID_INS_INSERTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_INSERTQ:
            tritonId = triton::arch::arm64::ID_INS_INSERTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_INSD:
            tritonId = triton::arch::arm64::ID_INS_INSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_INSW:
            tritonId = triton::arch::arm64::ID_INS_INSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_INT:
            tritonId = triton::arch::arm64::ID_INS_INT;
            break;

          case triton::extlibs::capstone::ARM64_INS_INT1:
            tritonId = triton::arch::arm64::ID_INS_INT1;
            break;

          case triton::extlibs::capstone::ARM64_INS_INT3:
            tritonId = triton::arch::arm64::ID_INS_INT3;
            break;

          case triton::extlibs::capstone::ARM64_INS_INTO:
            tritonId = triton::arch::arm64::ID_INS_INTO;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVD:
            tritonId = triton::arch::arm64::ID_INS_INVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVEPT:
            tritonId = triton::arch::arm64::ID_INS_INVEPT;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVLPG:
            tritonId = triton::arch::arm64::ID_INS_INVLPG;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVLPGA:
            tritonId = triton::arch::arm64::ID_INS_INVLPGA;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVPCID:
            tritonId = triton::arch::arm64::ID_INS_INVPCID;
            break;

          case triton::extlibs::capstone::ARM64_INS_INVVPID:
            tritonId = triton::arch::arm64::ID_INS_INVVPID;
            break;

          case triton::extlibs::capstone::ARM64_INS_IRET:
            tritonId = triton::arch::arm64::ID_INS_IRET;
            break;

          case triton::extlibs::capstone::ARM64_INS_IRETD:
            tritonId = triton::arch::arm64::ID_INS_IRETD;
            break;

          case triton::extlibs::capstone::ARM64_INS_IRETQ:
            tritonId = triton::arch::arm64::ID_INS_IRETQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_FISTTP:
            tritonId = triton::arch::arm64::ID_INS_FISTTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FIST:
            tritonId = triton::arch::arm64::ID_INS_FIST;
            break;

          case triton::extlibs::capstone::ARM64_INS_FISTP:
            tritonId = triton::arch::arm64::ID_INS_FISTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_UCOMISD:
            tritonId = triton::arch::arm64::ID_INS_UCOMISD;
            break;

          case triton::extlibs::capstone::ARM64_INS_UCOMISS:
            tritonId = triton::arch::arm64::ID_INS_UCOMISS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCMP:
            tritonId = triton::arch::arm64::ID_INS_VCMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCOMISD:
            tritonId = triton::arch::arm64::ID_INS_VCOMISD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCOMISS:
            tritonId = triton::arch::arm64::ID_INS_VCOMISS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSD2SS:
            tritonId = triton::arch::arm64::ID_INS_VCVTSD2SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSI2SD:
            tritonId = triton::arch::arm64::ID_INS_VCVTSI2SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSI2SS:
            tritonId = triton::arch::arm64::ID_INS_VCVTSI2SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSS2SD:
            tritonId = triton::arch::arm64::ID_INS_VCVTSS2SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTSD2SI:
            tritonId = triton::arch::arm64::ID_INS_VCVTTSD2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTSD2USI:
            tritonId = triton::arch::arm64::ID_INS_VCVTTSD2USI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTSS2SI:
            tritonId = triton::arch::arm64::ID_INS_VCVTTSS2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTSS2USI:
            tritonId = triton::arch::arm64::ID_INS_VCVTTSS2USI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTUSI2SD:
            tritonId = triton::arch::arm64::ID_INS_VCVTUSI2SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTUSI2SS:
            tritonId = triton::arch::arm64::ID_INS_VCVTUSI2SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUCOMISD:
            tritonId = triton::arch::arm64::ID_INS_VUCOMISD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUCOMISS:
            tritonId = triton::arch::arm64::ID_INS_VUCOMISS;
            break;

          case triton::extlibs::capstone::ARM64_INS_JAE:
            tritonId = triton::arch::arm64::ID_INS_JAE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JA:
            tritonId = triton::arch::arm64::ID_INS_JA;
            break;

          case triton::extlibs::capstone::ARM64_INS_JBE:
            tritonId = triton::arch::arm64::ID_INS_JBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JB:
            tritonId = triton::arch::arm64::ID_INS_JB;
            break;

          case triton::extlibs::capstone::ARM64_INS_JCXZ:
            tritonId = triton::arch::arm64::ID_INS_JCXZ;
            break;

          case triton::extlibs::capstone::ARM64_INS_JECXZ:
            tritonId = triton::arch::arm64::ID_INS_JECXZ;
            break;

          case triton::extlibs::capstone::ARM64_INS_JE:
            tritonId = triton::arch::arm64::ID_INS_JE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JGE:
            tritonId = triton::arch::arm64::ID_INS_JGE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JG:
            tritonId = triton::arch::arm64::ID_INS_JG;
            break;

          case triton::extlibs::capstone::ARM64_INS_JLE:
            tritonId = triton::arch::arm64::ID_INS_JLE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JL:
            tritonId = triton::arch::arm64::ID_INS_JL;
            break;

          case triton::extlibs::capstone::ARM64_INS_JMP:
            tritonId = triton::arch::arm64::ID_INS_JMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_JNE:
            tritonId = triton::arch::arm64::ID_INS_JNE;
            break;

          case triton::extlibs::capstone::ARM64_INS_JNO:
            tritonId = triton::arch::arm64::ID_INS_JNO;
            break;

          case triton::extlibs::capstone::ARM64_INS_JNP:
            tritonId = triton::arch::arm64::ID_INS_JNP;
            break;

          case triton::extlibs::capstone::ARM64_INS_JNS:
            tritonId = triton::arch::arm64::ID_INS_JNS;
            break;

          case triton::extlibs::capstone::ARM64_INS_JO:
            tritonId = triton::arch::arm64::ID_INS_JO;
            break;

          case triton::extlibs::capstone::ARM64_INS_JP:
            tritonId = triton::arch::arm64::ID_INS_JP;
            break;

          case triton::extlibs::capstone::ARM64_INS_JRCXZ:
            tritonId = triton::arch::arm64::ID_INS_JRCXZ;
            break;

          case triton::extlibs::capstone::ARM64_INS_JS:
            tritonId = triton::arch::arm64::ID_INS_JS;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDB:
            tritonId = triton::arch::arm64::ID_INS_KANDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDD:
            tritonId = triton::arch::arm64::ID_INS_KANDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDNB:
            tritonId = triton::arch::arm64::ID_INS_KANDNB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDND:
            tritonId = triton::arch::arm64::ID_INS_KANDND;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDNQ:
            tritonId = triton::arch::arm64::ID_INS_KANDNQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDNW:
            tritonId = triton::arch::arm64::ID_INS_KANDNW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDQ:
            tritonId = triton::arch::arm64::ID_INS_KANDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KANDW:
            tritonId = triton::arch::arm64::ID_INS_KANDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KMOVB:
            tritonId = triton::arch::arm64::ID_INS_KMOVB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KMOVD:
            tritonId = triton::arch::arm64::ID_INS_KMOVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KMOVQ:
            tritonId = triton::arch::arm64::ID_INS_KMOVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KMOVW:
            tritonId = triton::arch::arm64::ID_INS_KMOVW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KNOTB:
            tritonId = triton::arch::arm64::ID_INS_KNOTB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KNOTD:
            tritonId = triton::arch::arm64::ID_INS_KNOTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KNOTQ:
            tritonId = triton::arch::arm64::ID_INS_KNOTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KNOTW:
            tritonId = triton::arch::arm64::ID_INS_KNOTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KORB:
            tritonId = triton::arch::arm64::ID_INS_KORB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KORD:
            tritonId = triton::arch::arm64::ID_INS_KORD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KORQ:
            tritonId = triton::arch::arm64::ID_INS_KORQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KORTESTW:
            tritonId = triton::arch::arm64::ID_INS_KORTESTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KORW:
            tritonId = triton::arch::arm64::ID_INS_KORW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KSHIFTLW:
            tritonId = triton::arch::arm64::ID_INS_KSHIFTLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KSHIFTRW:
            tritonId = triton::arch::arm64::ID_INS_KSHIFTRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KUNPCKBW:
            tritonId = triton::arch::arm64::ID_INS_KUNPCKBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXNORB:
            tritonId = triton::arch::arm64::ID_INS_KXNORB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXNORD:
            tritonId = triton::arch::arm64::ID_INS_KXNORD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXNORQ:
            tritonId = triton::arch::arm64::ID_INS_KXNORQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXNORW:
            tritonId = triton::arch::arm64::ID_INS_KXNORW;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXORB:
            tritonId = triton::arch::arm64::ID_INS_KXORB;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXORD:
            tritonId = triton::arch::arm64::ID_INS_KXORD;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXORQ:
            tritonId = triton::arch::arm64::ID_INS_KXORQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_KXORW:
            tritonId = triton::arch::arm64::ID_INS_KXORW;
            break;

          case triton::extlibs::capstone::ARM64_INS_LAHF:
            tritonId = triton::arch::arm64::ID_INS_LAHF;
            break;

          case triton::extlibs::capstone::ARM64_INS_LAR:
            tritonId = triton::arch::arm64::ID_INS_LAR;
            break;

          case triton::extlibs::capstone::ARM64_INS_LDDQU:
            tritonId = triton::arch::arm64::ID_INS_LDDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_LDMXCSR:
            tritonId = triton::arch::arm64::ID_INS_LDMXCSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_LDS:
            tritonId = triton::arch::arm64::ID_INS_LDS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLDZ:
            tritonId = triton::arch::arm64::ID_INS_FLDZ;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLD1:
            tritonId = triton::arch::arm64::ID_INS_FLD1;
            break;

          case triton::extlibs::capstone::ARM64_INS_FLD:
            tritonId = triton::arch::arm64::ID_INS_FLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_LEA:
            tritonId = triton::arch::arm64::ID_INS_LEA;
            break;

          case triton::extlibs::capstone::ARM64_INS_LEAVE:
            tritonId = triton::arch::arm64::ID_INS_LEAVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_LES:
            tritonId = triton::arch::arm64::ID_INS_LES;
            break;

          case triton::extlibs::capstone::ARM64_INS_LFENCE:
            tritonId = triton::arch::arm64::ID_INS_LFENCE;
            break;

          case triton::extlibs::capstone::ARM64_INS_LFS:
            tritonId = triton::arch::arm64::ID_INS_LFS;
            break;

          case triton::extlibs::capstone::ARM64_INS_LGDT:
            tritonId = triton::arch::arm64::ID_INS_LGDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_LGS:
            tritonId = triton::arch::arm64::ID_INS_LGS;
            break;

          case triton::extlibs::capstone::ARM64_INS_LIDT:
            tritonId = triton::arch::arm64::ID_INS_LIDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_LLDT:
            tritonId = triton::arch::arm64::ID_INS_LLDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_LMSW:
            tritonId = triton::arch::arm64::ID_INS_LMSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_OR:
            tritonId = triton::arch::arm64::ID_INS_OR;
            break;

          case triton::extlibs::capstone::ARM64_INS_SUB:
            tritonId = triton::arch::arm64::ID_INS_SUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_XOR:
            tritonId = triton::arch::arm64::ID_INS_XOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_LODSB:
            tritonId = triton::arch::arm64::ID_INS_LODSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_LODSD:
            tritonId = triton::arch::arm64::ID_INS_LODSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_LODSQ:
            tritonId = triton::arch::arm64::ID_INS_LODSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_LODSW:
            tritonId = triton::arch::arm64::ID_INS_LODSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_LOOP:
            tritonId = triton::arch::arm64::ID_INS_LOOP;
            break;

          case triton::extlibs::capstone::ARM64_INS_LOOPE:
            tritonId = triton::arch::arm64::ID_INS_LOOPE;
            break;

          case triton::extlibs::capstone::ARM64_INS_LOOPNE:
            tritonId = triton::arch::arm64::ID_INS_LOOPNE;
            break;

          case triton::extlibs::capstone::ARM64_INS_RETF:
            tritonId = triton::arch::arm64::ID_INS_RETF;
            break;

          case triton::extlibs::capstone::ARM64_INS_RETFQ:
            tritonId = triton::arch::arm64::ID_INS_RETFQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_LSL:
            tritonId = triton::arch::arm64::ID_INS_LSL;
            break;

          case triton::extlibs::capstone::ARM64_INS_LSS:
            tritonId = triton::arch::arm64::ID_INS_LSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_LTR:
            tritonId = triton::arch::arm64::ID_INS_LTR;
            break;

          case triton::extlibs::capstone::ARM64_INS_XADD:
            tritonId = triton::arch::arm64::ID_INS_XADD;
            break;

          case triton::extlibs::capstone::ARM64_INS_LZCNT:
            tritonId = triton::arch::arm64::ID_INS_LZCNT;
            break;

          case triton::extlibs::capstone::ARM64_INS_MASKMOVDQU:
            tritonId = triton::arch::arm64::ID_INS_MASKMOVDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_MAXPD:
            tritonId = triton::arch::arm64::ID_INS_MAXPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MAXPS:
            tritonId = triton::arch::arm64::ID_INS_MAXPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MAXSD:
            tritonId = triton::arch::arm64::ID_INS_MAXSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MAXSS:
            tritonId = triton::arch::arm64::ID_INS_MAXSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MFENCE:
            tritonId = triton::arch::arm64::ID_INS_MFENCE;
            break;

          case triton::extlibs::capstone::ARM64_INS_MINPD:
            tritonId = triton::arch::arm64::ID_INS_MINPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MINPS:
            tritonId = triton::arch::arm64::ID_INS_MINPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MINSD:
            tritonId = triton::arch::arm64::ID_INS_MINSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MINSS:
            tritonId = triton::arch::arm64::ID_INS_MINSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPD2PI:
            tritonId = triton::arch::arm64::ID_INS_CVTPD2PI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPI2PD:
            tritonId = triton::arch::arm64::ID_INS_CVTPI2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPI2PS:
            tritonId = triton::arch::arm64::ID_INS_CVTPI2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTPS2PI:
            tritonId = triton::arch::arm64::ID_INS_CVTPS2PI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTPD2PI:
            tritonId = triton::arch::arm64::ID_INS_CVTTPD2PI;
            break;

          case triton::extlibs::capstone::ARM64_INS_CVTTPS2PI:
            tritonId = triton::arch::arm64::ID_INS_CVTTPS2PI;
            break;

          case triton::extlibs::capstone::ARM64_INS_EMMS:
            tritonId = triton::arch::arm64::ID_INS_EMMS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MASKMOVQ:
            tritonId = triton::arch::arm64::ID_INS_MASKMOVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVD:
            tritonId = triton::arch::arm64::ID_INS_MOVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVDQ2Q:
            tritonId = triton::arch::arm64::ID_INS_MOVDQ2Q;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTQ:
            tritonId = triton::arch::arm64::ID_INS_MOVNTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVQ2DQ:
            tritonId = triton::arch::arm64::ID_INS_MOVQ2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVQ:
            tritonId = triton::arch::arm64::ID_INS_MOVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PABSB:
            tritonId = triton::arch::arm64::ID_INS_PABSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PABSD:
            tritonId = triton::arch::arm64::ID_INS_PABSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PABSW:
            tritonId = triton::arch::arm64::ID_INS_PABSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PACKSSDW:
            tritonId = triton::arch::arm64::ID_INS_PACKSSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PACKSSWB:
            tritonId = triton::arch::arm64::ID_INS_PACKSSWB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PACKUSWB:
            tritonId = triton::arch::arm64::ID_INS_PACKUSWB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDB:
            tritonId = triton::arch::arm64::ID_INS_PADDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDD:
            tritonId = triton::arch::arm64::ID_INS_PADDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDQ:
            tritonId = triton::arch::arm64::ID_INS_PADDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDSB:
            tritonId = triton::arch::arm64::ID_INS_PADDSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDSW:
            tritonId = triton::arch::arm64::ID_INS_PADDSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDUSB:
            tritonId = triton::arch::arm64::ID_INS_PADDUSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDUSW:
            tritonId = triton::arch::arm64::ID_INS_PADDUSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PADDW:
            tritonId = triton::arch::arm64::ID_INS_PADDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PALIGNR:
            tritonId = triton::arch::arm64::ID_INS_PALIGNR;
            break;

          case triton::extlibs::capstone::ARM64_INS_PANDN:
            tritonId = triton::arch::arm64::ID_INS_PANDN;
            break;

          case triton::extlibs::capstone::ARM64_INS_PAND:
            tritonId = triton::arch::arm64::ID_INS_PAND;
            break;

          case triton::extlibs::capstone::ARM64_INS_PAVGB:
            tritonId = triton::arch::arm64::ID_INS_PAVGB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PAVGW:
            tritonId = triton::arch::arm64::ID_INS_PAVGW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPEQB:
            tritonId = triton::arch::arm64::ID_INS_PCMPEQB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPEQD:
            tritonId = triton::arch::arm64::ID_INS_PCMPEQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPEQW:
            tritonId = triton::arch::arm64::ID_INS_PCMPEQW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPGTB:
            tritonId = triton::arch::arm64::ID_INS_PCMPGTB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPGTD:
            tritonId = triton::arch::arm64::ID_INS_PCMPGTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPGTW:
            tritonId = triton::arch::arm64::ID_INS_PCMPGTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PEXTRW:
            tritonId = triton::arch::arm64::ID_INS_PEXTRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHADDSW:
            tritonId = triton::arch::arm64::ID_INS_PHADDSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHADDW:
            tritonId = triton::arch::arm64::ID_INS_PHADDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHADDD:
            tritonId = triton::arch::arm64::ID_INS_PHADDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHSUBD:
            tritonId = triton::arch::arm64::ID_INS_PHSUBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHSUBSW:
            tritonId = triton::arch::arm64::ID_INS_PHSUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHSUBW:
            tritonId = triton::arch::arm64::ID_INS_PHSUBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PINSRW:
            tritonId = triton::arch::arm64::ID_INS_PINSRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMADDUBSW:
            tritonId = triton::arch::arm64::ID_INS_PMADDUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMADDWD:
            tritonId = triton::arch::arm64::ID_INS_PMADDWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXSW:
            tritonId = triton::arch::arm64::ID_INS_PMAXSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXUB:
            tritonId = triton::arch::arm64::ID_INS_PMAXUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINSW:
            tritonId = triton::arch::arm64::ID_INS_PMINSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINUB:
            tritonId = triton::arch::arm64::ID_INS_PMINUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVMSKB:
            tritonId = triton::arch::arm64::ID_INS_PMOVMSKB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULHRSW:
            tritonId = triton::arch::arm64::ID_INS_PMULHRSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULHUW:
            tritonId = triton::arch::arm64::ID_INS_PMULHUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULHW:
            tritonId = triton::arch::arm64::ID_INS_PMULHW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULLW:
            tritonId = triton::arch::arm64::ID_INS_PMULLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULUDQ:
            tritonId = triton::arch::arm64::ID_INS_PMULUDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_POR:
            tritonId = triton::arch::arm64::ID_INS_POR;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSADBW:
            tritonId = triton::arch::arm64::ID_INS_PSADBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSHUFB:
            tritonId = triton::arch::arm64::ID_INS_PSHUFB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSHUFW:
            tritonId = triton::arch::arm64::ID_INS_PSHUFW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSIGNB:
            tritonId = triton::arch::arm64::ID_INS_PSIGNB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSIGND:
            tritonId = triton::arch::arm64::ID_INS_PSIGND;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSIGNW:
            tritonId = triton::arch::arm64::ID_INS_PSIGNW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSLLD:
            tritonId = triton::arch::arm64::ID_INS_PSLLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSLLQ:
            tritonId = triton::arch::arm64::ID_INS_PSLLQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSLLW:
            tritonId = triton::arch::arm64::ID_INS_PSLLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRAD:
            tritonId = triton::arch::arm64::ID_INS_PSRAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRAW:
            tritonId = triton::arch::arm64::ID_INS_PSRAW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRLD:
            tritonId = triton::arch::arm64::ID_INS_PSRLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRLQ:
            tritonId = triton::arch::arm64::ID_INS_PSRLQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRLW:
            tritonId = triton::arch::arm64::ID_INS_PSRLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBB:
            tritonId = triton::arch::arm64::ID_INS_PSUBB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBD:
            tritonId = triton::arch::arm64::ID_INS_PSUBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBQ:
            tritonId = triton::arch::arm64::ID_INS_PSUBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBSB:
            tritonId = triton::arch::arm64::ID_INS_PSUBSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBSW:
            tritonId = triton::arch::arm64::ID_INS_PSUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBUSB:
            tritonId = triton::arch::arm64::ID_INS_PSUBUSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBUSW:
            tritonId = triton::arch::arm64::ID_INS_PSUBUSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSUBW:
            tritonId = triton::arch::arm64::ID_INS_PSUBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKHBW:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKHBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKHDQ:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKHDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKHWD:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKHWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKLBW:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKLBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKLDQ:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKLWD:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKLWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PXOR:
            tritonId = triton::arch::arm64::ID_INS_PXOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_MONITOR:
            tritonId = triton::arch::arm64::ID_INS_MONITOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_MONTMUL:
            tritonId = triton::arch::arm64::ID_INS_MONTMUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOV:
            tritonId = triton::arch::arm64::ID_INS_MOV;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVABS:
            tritonId = triton::arch::arm64::ID_INS_MOVABS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVBE:
            tritonId = triton::arch::arm64::ID_INS_MOVBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVDDUP:
            tritonId = triton::arch::arm64::ID_INS_MOVDDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVDQA:
            tritonId = triton::arch::arm64::ID_INS_MOVDQA;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVDQU:
            tritonId = triton::arch::arm64::ID_INS_MOVDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVHLPS:
            tritonId = triton::arch::arm64::ID_INS_MOVHLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVHPD:
            tritonId = triton::arch::arm64::ID_INS_MOVHPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVHPS:
            tritonId = triton::arch::arm64::ID_INS_MOVHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVLHPS:
            tritonId = triton::arch::arm64::ID_INS_MOVLHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVLPD:
            tritonId = triton::arch::arm64::ID_INS_MOVLPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVLPS:
            tritonId = triton::arch::arm64::ID_INS_MOVLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVMSKPD:
            tritonId = triton::arch::arm64::ID_INS_MOVMSKPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVMSKPS:
            tritonId = triton::arch::arm64::ID_INS_MOVMSKPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTDQA:
            tritonId = triton::arch::arm64::ID_INS_MOVNTDQA;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTDQ:
            tritonId = triton::arch::arm64::ID_INS_MOVNTDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTI:
            tritonId = triton::arch::arm64::ID_INS_MOVNTI;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTPD:
            tritonId = triton::arch::arm64::ID_INS_MOVNTPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTPS:
            tritonId = triton::arch::arm64::ID_INS_MOVNTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTSD:
            tritonId = triton::arch::arm64::ID_INS_MOVNTSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVNTSS:
            tritonId = triton::arch::arm64::ID_INS_MOVNTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSB:
            tritonId = triton::arch::arm64::ID_INS_MOVSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSD:
            tritonId = triton::arch::arm64::ID_INS_MOVSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSHDUP:
            tritonId = triton::arch::arm64::ID_INS_MOVSHDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSLDUP:
            tritonId = triton::arch::arm64::ID_INS_MOVSLDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSQ:
            tritonId = triton::arch::arm64::ID_INS_MOVSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSS:
            tritonId = triton::arch::arm64::ID_INS_MOVSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSW:
            tritonId = triton::arch::arm64::ID_INS_MOVSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSX:
            tritonId = triton::arch::arm64::ID_INS_MOVSX;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVSXD:
            tritonId = triton::arch::arm64::ID_INS_MOVSXD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVUPD:
            tritonId = triton::arch::arm64::ID_INS_MOVUPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVUPS:
            tritonId = triton::arch::arm64::ID_INS_MOVUPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MOVZX:
            tritonId = triton::arch::arm64::ID_INS_MOVZX;
            break;

          case triton::extlibs::capstone::ARM64_INS_MPSADBW:
            tritonId = triton::arch::arm64::ID_INS_MPSADBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_MUL:
            tritonId = triton::arch::arm64::ID_INS_MUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_MULPD:
            tritonId = triton::arch::arm64::ID_INS_MULPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MULPS:
            tritonId = triton::arch::arm64::ID_INS_MULPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MULSD:
            tritonId = triton::arch::arm64::ID_INS_MULSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_MULSS:
            tritonId = triton::arch::arm64::ID_INS_MULSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_MULX:
            tritonId = triton::arch::arm64::ID_INS_MULX;
            break;

          case triton::extlibs::capstone::ARM64_INS_FMUL:
            tritonId = triton::arch::arm64::ID_INS_FMUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_FIMUL:
            tritonId = triton::arch::arm64::ID_INS_FIMUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_FMULP:
            tritonId = triton::arch::arm64::ID_INS_FMULP;
            break;

          case triton::extlibs::capstone::ARM64_INS_MWAIT:
            tritonId = triton::arch::arm64::ID_INS_MWAIT;
            break;

          case triton::extlibs::capstone::ARM64_INS_NEG:
            tritonId = triton::arch::arm64::ID_INS_NEG;
            break;

          case triton::extlibs::capstone::ARM64_INS_NOP:
            tritonId = triton::arch::arm64::ID_INS_NOP;
            break;

          case triton::extlibs::capstone::ARM64_INS_NOT:
            tritonId = triton::arch::arm64::ID_INS_NOT;
            break;

          case triton::extlibs::capstone::ARM64_INS_OUT:
            tritonId = triton::arch::arm64::ID_INS_OUT;
            break;

          case triton::extlibs::capstone::ARM64_INS_OUTSB:
            tritonId = triton::arch::arm64::ID_INS_OUTSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_OUTSD:
            tritonId = triton::arch::arm64::ID_INS_OUTSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_OUTSW:
            tritonId = triton::arch::arm64::ID_INS_OUTSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PACKUSDW:
            tritonId = triton::arch::arm64::ID_INS_PACKUSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PAUSE:
            tritonId = triton::arch::arm64::ID_INS_PAUSE;
            break;

          case triton::extlibs::capstone::ARM64_INS_PAVGUSB:
            tritonId = triton::arch::arm64::ID_INS_PAVGUSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PBLENDVB:
            tritonId = triton::arch::arm64::ID_INS_PBLENDVB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PBLENDW:
            tritonId = triton::arch::arm64::ID_INS_PBLENDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCLMULQDQ:
            tritonId = triton::arch::arm64::ID_INS_PCLMULQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPEQQ:
            tritonId = triton::arch::arm64::ID_INS_PCMPEQQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPESTRI:
            tritonId = triton::arch::arm64::ID_INS_PCMPESTRI;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPESTRM:
            tritonId = triton::arch::arm64::ID_INS_PCMPESTRM;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPGTQ:
            tritonId = triton::arch::arm64::ID_INS_PCMPGTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPISTRI:
            tritonId = triton::arch::arm64::ID_INS_PCMPISTRI;
            break;

          case triton::extlibs::capstone::ARM64_INS_PCMPISTRM:
            tritonId = triton::arch::arm64::ID_INS_PCMPISTRM;
            break;

          case triton::extlibs::capstone::ARM64_INS_PDEP:
            tritonId = triton::arch::arm64::ID_INS_PDEP;
            break;

          case triton::extlibs::capstone::ARM64_INS_PEXT:
            tritonId = triton::arch::arm64::ID_INS_PEXT;
            break;

          case triton::extlibs::capstone::ARM64_INS_PEXTRB:
            tritonId = triton::arch::arm64::ID_INS_PEXTRB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PEXTRD:
            tritonId = triton::arch::arm64::ID_INS_PEXTRD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PEXTRQ:
            tritonId = triton::arch::arm64::ID_INS_PEXTRQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PF2ID:
            tritonId = triton::arch::arm64::ID_INS_PF2ID;
            break;

          case triton::extlibs::capstone::ARM64_INS_PF2IW:
            tritonId = triton::arch::arm64::ID_INS_PF2IW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFACC:
            tritonId = triton::arch::arm64::ID_INS_PFACC;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFADD:
            tritonId = triton::arch::arm64::ID_INS_PFADD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFCMPEQ:
            tritonId = triton::arch::arm64::ID_INS_PFCMPEQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFCMPGE:
            tritonId = triton::arch::arm64::ID_INS_PFCMPGE;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFCMPGT:
            tritonId = triton::arch::arm64::ID_INS_PFCMPGT;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFMAX:
            tritonId = triton::arch::arm64::ID_INS_PFMAX;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFMIN:
            tritonId = triton::arch::arm64::ID_INS_PFMIN;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFMUL:
            tritonId = triton::arch::arm64::ID_INS_PFMUL;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFNACC:
            tritonId = triton::arch::arm64::ID_INS_PFNACC;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFPNACC:
            tritonId = triton::arch::arm64::ID_INS_PFPNACC;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFRCPIT1:
            tritonId = triton::arch::arm64::ID_INS_PFRCPIT1;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFRCPIT2:
            tritonId = triton::arch::arm64::ID_INS_PFRCPIT2;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFRCP:
            tritonId = triton::arch::arm64::ID_INS_PFRCP;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFRSQIT1:
            tritonId = triton::arch::arm64::ID_INS_PFRSQIT1;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFRSQRT:
            tritonId = triton::arch::arm64::ID_INS_PFRSQRT;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFSUBR:
            tritonId = triton::arch::arm64::ID_INS_PFSUBR;
            break;

          case triton::extlibs::capstone::ARM64_INS_PFSUB:
            tritonId = triton::arch::arm64::ID_INS_PFSUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PHMINPOSUW:
            tritonId = triton::arch::arm64::ID_INS_PHMINPOSUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PI2FD:
            tritonId = triton::arch::arm64::ID_INS_PI2FD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PI2FW:
            tritonId = triton::arch::arm64::ID_INS_PI2FW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PINSRB:
            tritonId = triton::arch::arm64::ID_INS_PINSRB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PINSRD:
            tritonId = triton::arch::arm64::ID_INS_PINSRD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PINSRQ:
            tritonId = triton::arch::arm64::ID_INS_PINSRQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXSB:
            tritonId = triton::arch::arm64::ID_INS_PMAXSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXSD:
            tritonId = triton::arch::arm64::ID_INS_PMAXSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXUD:
            tritonId = triton::arch::arm64::ID_INS_PMAXUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMAXUW:
            tritonId = triton::arch::arm64::ID_INS_PMAXUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINSB:
            tritonId = triton::arch::arm64::ID_INS_PMINSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINSD:
            tritonId = triton::arch::arm64::ID_INS_PMINSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINUD:
            tritonId = triton::arch::arm64::ID_INS_PMINUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMINUW:
            tritonId = triton::arch::arm64::ID_INS_PMINUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXBD:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXBQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXBW:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXDQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXWD:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVSXWQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVSXWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXBD:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXBQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXBW:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXDQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXWD:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMOVZXWQ:
            tritonId = triton::arch::arm64::ID_INS_PMOVZXWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULDQ:
            tritonId = triton::arch::arm64::ID_INS_PMULDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULHRW:
            tritonId = triton::arch::arm64::ID_INS_PMULHRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PMULLD:
            tritonId = triton::arch::arm64::ID_INS_PMULLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_POP:
            tritonId = triton::arch::arm64::ID_INS_POP;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPAW:
            tritonId = triton::arch::arm64::ID_INS_POPAW;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPAL:
            tritonId = triton::arch::arm64::ID_INS_POPAL;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPCNT:
            tritonId = triton::arch::arm64::ID_INS_POPCNT;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPF:
            tritonId = triton::arch::arm64::ID_INS_POPF;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPFD:
            tritonId = triton::arch::arm64::ID_INS_POPFD;
            break;

          case triton::extlibs::capstone::ARM64_INS_POPFQ:
            tritonId = triton::arch::arm64::ID_INS_POPFQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCH:
            tritonId = triton::arch::arm64::ID_INS_PREFETCH;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCHNTA:
            tritonId = triton::arch::arm64::ID_INS_PREFETCHNTA;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCHT0:
            tritonId = triton::arch::arm64::ID_INS_PREFETCHT0;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCHT1:
            tritonId = triton::arch::arm64::ID_INS_PREFETCHT1;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCHT2:
            tritonId = triton::arch::arm64::ID_INS_PREFETCHT2;
            break;

          case triton::extlibs::capstone::ARM64_INS_PREFETCHW:
            tritonId = triton::arch::arm64::ID_INS_PREFETCHW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSHUFD:
            tritonId = triton::arch::arm64::ID_INS_PSHUFD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSHUFHW:
            tritonId = triton::arch::arm64::ID_INS_PSHUFHW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSHUFLW:
            tritonId = triton::arch::arm64::ID_INS_PSHUFLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSLLDQ:
            tritonId = triton::arch::arm64::ID_INS_PSLLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSRLDQ:
            tritonId = triton::arch::arm64::ID_INS_PSRLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PSWAPD:
            tritonId = triton::arch::arm64::ID_INS_PSWAPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PTEST:
            tritonId = triton::arch::arm64::ID_INS_PTEST;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKHQDQ:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKHQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUNPCKLQDQ:
            tritonId = triton::arch::arm64::ID_INS_PUNPCKLQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSH:
            tritonId = triton::arch::arm64::ID_INS_PUSH;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSHAW:
            tritonId = triton::arch::arm64::ID_INS_PUSHAW;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSHAL:
            tritonId = triton::arch::arm64::ID_INS_PUSHAL;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSHF:
            tritonId = triton::arch::arm64::ID_INS_PUSHF;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSHFD:
            tritonId = triton::arch::arm64::ID_INS_PUSHFD;
            break;

          case triton::extlibs::capstone::ARM64_INS_PUSHFQ:
            tritonId = triton::arch::arm64::ID_INS_PUSHFQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_RCL:
            tritonId = triton::arch::arm64::ID_INS_RCL;
            break;

          case triton::extlibs::capstone::ARM64_INS_RCPPS:
            tritonId = triton::arch::arm64::ID_INS_RCPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_RCPSS:
            tritonId = triton::arch::arm64::ID_INS_RCPSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_RCR:
            tritonId = triton::arch::arm64::ID_INS_RCR;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDFSBASE:
            tritonId = triton::arch::arm64::ID_INS_RDFSBASE;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDGSBASE:
            tritonId = triton::arch::arm64::ID_INS_RDGSBASE;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDMSR:
            tritonId = triton::arch::arm64::ID_INS_RDMSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDPMC:
            tritonId = triton::arch::arm64::ID_INS_RDPMC;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDRAND:
            tritonId = triton::arch::arm64::ID_INS_RDRAND;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDSEED:
            tritonId = triton::arch::arm64::ID_INS_RDSEED;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDTSC:
            tritonId = triton::arch::arm64::ID_INS_RDTSC;
            break;

          case triton::extlibs::capstone::ARM64_INS_RDTSCP:
            tritonId = triton::arch::arm64::ID_INS_RDTSCP;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROL:
            tritonId = triton::arch::arm64::ID_INS_ROL;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROR:
            tritonId = triton::arch::arm64::ID_INS_ROR;
            break;

          case triton::extlibs::capstone::ARM64_INS_RORX:
            tritonId = triton::arch::arm64::ID_INS_RORX;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROUNDPD:
            tritonId = triton::arch::arm64::ID_INS_ROUNDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROUNDPS:
            tritonId = triton::arch::arm64::ID_INS_ROUNDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROUNDSD:
            tritonId = triton::arch::arm64::ID_INS_ROUNDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_ROUNDSS:
            tritonId = triton::arch::arm64::ID_INS_ROUNDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_RSM:
            tritonId = triton::arch::arm64::ID_INS_RSM;
            break;

          case triton::extlibs::capstone::ARM64_INS_RSQRTPS:
            tritonId = triton::arch::arm64::ID_INS_RSQRTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_RSQRTSS:
            tritonId = triton::arch::arm64::ID_INS_RSQRTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SAHF:
            tritonId = triton::arch::arm64::ID_INS_SAHF;
            break;

          case triton::extlibs::capstone::ARM64_INS_SAL:
            tritonId = triton::arch::arm64::ID_INS_SAL;
            break;

          case triton::extlibs::capstone::ARM64_INS_SALC:
            tritonId = triton::arch::arm64::ID_INS_SALC;
            break;

          case triton::extlibs::capstone::ARM64_INS_SAR:
            tritonId = triton::arch::arm64::ID_INS_SAR;
            break;

          case triton::extlibs::capstone::ARM64_INS_SARX:
            tritonId = triton::arch::arm64::ID_INS_SARX;
            break;

          case triton::extlibs::capstone::ARM64_INS_SBB:
            tritonId = triton::arch::arm64::ID_INS_SBB;
            break;

          case triton::extlibs::capstone::ARM64_INS_SCASB:
            tritonId = triton::arch::arm64::ID_INS_SCASB;
            break;

          case triton::extlibs::capstone::ARM64_INS_SCASD:
            tritonId = triton::arch::arm64::ID_INS_SCASD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SCASQ:
            tritonId = triton::arch::arm64::ID_INS_SCASQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_SCASW:
            tritonId = triton::arch::arm64::ID_INS_SCASW;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETAE:
            tritonId = triton::arch::arm64::ID_INS_SETAE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETA:
            tritonId = triton::arch::arm64::ID_INS_SETA;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETBE:
            tritonId = triton::arch::arm64::ID_INS_SETBE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETB:
            tritonId = triton::arch::arm64::ID_INS_SETB;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETE:
            tritonId = triton::arch::arm64::ID_INS_SETE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETGE:
            tritonId = triton::arch::arm64::ID_INS_SETGE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETG:
            tritonId = triton::arch::arm64::ID_INS_SETG;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETLE:
            tritonId = triton::arch::arm64::ID_INS_SETLE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETL:
            tritonId = triton::arch::arm64::ID_INS_SETL;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETNE:
            tritonId = triton::arch::arm64::ID_INS_SETNE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETNO:
            tritonId = triton::arch::arm64::ID_INS_SETNO;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETNP:
            tritonId = triton::arch::arm64::ID_INS_SETNP;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETNS:
            tritonId = triton::arch::arm64::ID_INS_SETNS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETO:
            tritonId = triton::arch::arm64::ID_INS_SETO;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETP:
            tritonId = triton::arch::arm64::ID_INS_SETP;
            break;

          case triton::extlibs::capstone::ARM64_INS_SETS:
            tritonId = triton::arch::arm64::ID_INS_SETS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SFENCE:
            tritonId = triton::arch::arm64::ID_INS_SFENCE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SGDT:
            tritonId = triton::arch::arm64::ID_INS_SGDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA1MSG1:
            tritonId = triton::arch::arm64::ID_INS_SHA1MSG1;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA1MSG2:
            tritonId = triton::arch::arm64::ID_INS_SHA1MSG2;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA1NEXTE:
            tritonId = triton::arch::arm64::ID_INS_SHA1NEXTE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA1RNDS4:
            tritonId = triton::arch::arm64::ID_INS_SHA1RNDS4;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA256MSG1:
            tritonId = triton::arch::arm64::ID_INS_SHA256MSG1;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA256MSG2:
            tritonId = triton::arch::arm64::ID_INS_SHA256MSG2;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHA256RNDS2:
            tritonId = triton::arch::arm64::ID_INS_SHA256RNDS2;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHL:
            tritonId = triton::arch::arm64::ID_INS_SHL;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHLD:
            tritonId = triton::arch::arm64::ID_INS_SHLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHLX:
            tritonId = triton::arch::arm64::ID_INS_SHLX;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHR:
            tritonId = triton::arch::arm64::ID_INS_SHR;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHRD:
            tritonId = triton::arch::arm64::ID_INS_SHRD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHRX:
            tritonId = triton::arch::arm64::ID_INS_SHRX;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHUFPD:
            tritonId = triton::arch::arm64::ID_INS_SHUFPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SHUFPS:
            tritonId = triton::arch::arm64::ID_INS_SHUFPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SIDT:
            tritonId = triton::arch::arm64::ID_INS_SIDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSIN:
            tritonId = triton::arch::arm64::ID_INS_FSIN;
            break;

          case triton::extlibs::capstone::ARM64_INS_SKINIT:
            tritonId = triton::arch::arm64::ID_INS_SKINIT;
            break;

          case triton::extlibs::capstone::ARM64_INS_SLDT:
            tritonId = triton::arch::arm64::ID_INS_SLDT;
            break;

          case triton::extlibs::capstone::ARM64_INS_SMSW:
            tritonId = triton::arch::arm64::ID_INS_SMSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_SQRTPD:
            tritonId = triton::arch::arm64::ID_INS_SQRTPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SQRTPS:
            tritonId = triton::arch::arm64::ID_INS_SQRTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SQRTSD:
            tritonId = triton::arch::arm64::ID_INS_SQRTSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SQRTSS:
            tritonId = triton::arch::arm64::ID_INS_SQRTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSQRT:
            tritonId = triton::arch::arm64::ID_INS_FSQRT;
            break;

          case triton::extlibs::capstone::ARM64_INS_STAC:
            tritonId = triton::arch::arm64::ID_INS_STAC;
            break;

          case triton::extlibs::capstone::ARM64_INS_STC:
            tritonId = triton::arch::arm64::ID_INS_STC;
            break;

          case triton::extlibs::capstone::ARM64_INS_STD:
            tritonId = triton::arch::arm64::ID_INS_STD;
            break;

          case triton::extlibs::capstone::ARM64_INS_STGI:
            tritonId = triton::arch::arm64::ID_INS_STGI;
            break;

          case triton::extlibs::capstone::ARM64_INS_STI:
            tritonId = triton::arch::arm64::ID_INS_STI;
            break;

          case triton::extlibs::capstone::ARM64_INS_STMXCSR:
            tritonId = triton::arch::arm64::ID_INS_STMXCSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_STOSB:
            tritonId = triton::arch::arm64::ID_INS_STOSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_STOSD:
            tritonId = triton::arch::arm64::ID_INS_STOSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_STOSQ:
            tritonId = triton::arch::arm64::ID_INS_STOSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_STOSW:
            tritonId = triton::arch::arm64::ID_INS_STOSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_STR:
            tritonId = triton::arch::arm64::ID_INS_STR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FST:
            tritonId = triton::arch::arm64::ID_INS_FST;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSTP:
            tritonId = triton::arch::arm64::ID_INS_FSTP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSTPNCE:
            tritonId = triton::arch::arm64::ID_INS_FSTPNCE;
            break;

          case triton::extlibs::capstone::ARM64_INS_SUBPD:
            tritonId = triton::arch::arm64::ID_INS_SUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SUBPS:
            tritonId = triton::arch::arm64::ID_INS_SUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSUBR:
            tritonId = triton::arch::arm64::ID_INS_FSUBR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FISUBR:
            tritonId = triton::arch::arm64::ID_INS_FISUBR;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSUBRP:
            tritonId = triton::arch::arm64::ID_INS_FSUBRP;
            break;

          case triton::extlibs::capstone::ARM64_INS_SUBSD:
            tritonId = triton::arch::arm64::ID_INS_SUBSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_SUBSS:
            tritonId = triton::arch::arm64::ID_INS_SUBSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSUB:
            tritonId = triton::arch::arm64::ID_INS_FSUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_FISUB:
            tritonId = triton::arch::arm64::ID_INS_FISUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_FSUBP:
            tritonId = triton::arch::arm64::ID_INS_FSUBP;
            break;

          case triton::extlibs::capstone::ARM64_INS_SWAPGS:
            tritonId = triton::arch::arm64::ID_INS_SWAPGS;
            break;

          case triton::extlibs::capstone::ARM64_INS_SYSCALL:
            tritonId = triton::arch::arm64::ID_INS_SYSCALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_SYSENTER:
            tritonId = triton::arch::arm64::ID_INS_SYSENTER;
            break;

          case triton::extlibs::capstone::ARM64_INS_SYSEXIT:
            tritonId = triton::arch::arm64::ID_INS_SYSEXIT;
            break;

          case triton::extlibs::capstone::ARM64_INS_SYSRET:
            tritonId = triton::arch::arm64::ID_INS_SYSRET;
            break;

          case triton::extlibs::capstone::ARM64_INS_T1MSKC:
            tritonId = triton::arch::arm64::ID_INS_T1MSKC;
            break;

          case triton::extlibs::capstone::ARM64_INS_TEST:
            tritonId = triton::arch::arm64::ID_INS_TEST;
            break;

          case triton::extlibs::capstone::ARM64_INS_UD2:
            tritonId = triton::arch::arm64::ID_INS_UD2;
            break;

          case triton::extlibs::capstone::ARM64_INS_FTST:
            tritonId = triton::arch::arm64::ID_INS_FTST;
            break;

          case triton::extlibs::capstone::ARM64_INS_TZCNT:
            tritonId = triton::arch::arm64::ID_INS_TZCNT;
            break;

          case triton::extlibs::capstone::ARM64_INS_TZMSK:
            tritonId = triton::arch::arm64::ID_INS_TZMSK;
            break;

          case triton::extlibs::capstone::ARM64_INS_FUCOMPI:
            tritonId = triton::arch::arm64::ID_INS_FUCOMPI;
            break;

          case triton::extlibs::capstone::ARM64_INS_FUCOMI:
            tritonId = triton::arch::arm64::ID_INS_FUCOMI;
            break;

          case triton::extlibs::capstone::ARM64_INS_FUCOMPP:
            tritonId = triton::arch::arm64::ID_INS_FUCOMPP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FUCOMP:
            tritonId = triton::arch::arm64::ID_INS_FUCOMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_FUCOM:
            tritonId = triton::arch::arm64::ID_INS_FUCOM;
            break;

          case triton::extlibs::capstone::ARM64_INS_UD2B:
            tritonId = triton::arch::arm64::ID_INS_UD2B;
            break;

          case triton::extlibs::capstone::ARM64_INS_UNPCKHPD:
            tritonId = triton::arch::arm64::ID_INS_UNPCKHPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_UNPCKHPS:
            tritonId = triton::arch::arm64::ID_INS_UNPCKHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_UNPCKLPD:
            tritonId = triton::arch::arm64::ID_INS_UNPCKLPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_UNPCKLPS:
            tritonId = triton::arch::arm64::ID_INS_UNPCKLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDPD:
            tritonId = triton::arch::arm64::ID_INS_VADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDPS:
            tritonId = triton::arch::arm64::ID_INS_VADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDSD:
            tritonId = triton::arch::arm64::ID_INS_VADDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDSS:
            tritonId = triton::arch::arm64::ID_INS_VADDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VADDSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VADDSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VADDSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESDECLAST:
            tritonId = triton::arch::arm64::ID_INS_VAESDECLAST;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESDEC:
            tritonId = triton::arch::arm64::ID_INS_VAESDEC;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESENCLAST:
            tritonId = triton::arch::arm64::ID_INS_VAESENCLAST;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESENC:
            tritonId = triton::arch::arm64::ID_INS_VAESENC;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESIMC:
            tritonId = triton::arch::arm64::ID_INS_VAESIMC;
            break;

          case triton::extlibs::capstone::ARM64_INS_VAESKEYGENASSIST:
            tritonId = triton::arch::arm64::ID_INS_VAESKEYGENASSIST;
            break;

          case triton::extlibs::capstone::ARM64_INS_VALIGND:
            tritonId = triton::arch::arm64::ID_INS_VALIGND;
            break;

          case triton::extlibs::capstone::ARM64_INS_VALIGNQ:
            tritonId = triton::arch::arm64::ID_INS_VALIGNQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VANDNPD:
            tritonId = triton::arch::arm64::ID_INS_VANDNPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VANDNPS:
            tritonId = triton::arch::arm64::ID_INS_VANDNPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VANDPD:
            tritonId = triton::arch::arm64::ID_INS_VANDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VANDPS:
            tritonId = triton::arch::arm64::ID_INS_VANDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDMPD:
            tritonId = triton::arch::arm64::ID_INS_VBLENDMPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDMPS:
            tritonId = triton::arch::arm64::ID_INS_VBLENDMPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDPD:
            tritonId = triton::arch::arm64::ID_INS_VBLENDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDPS:
            tritonId = triton::arch::arm64::ID_INS_VBLENDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDVPD:
            tritonId = triton::arch::arm64::ID_INS_VBLENDVPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBLENDVPS:
            tritonId = triton::arch::arm64::ID_INS_VBLENDVPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTF128:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTF128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTI128:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTI128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTI32X4:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTI32X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTI64X4:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTI64X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTSD:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VBROADCASTSS:
            tritonId = triton::arch::arm64::ID_INS_VBROADCASTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCMPPD:
            tritonId = triton::arch::arm64::ID_INS_VCMPPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCMPPS:
            tritonId = triton::arch::arm64::ID_INS_VCMPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCMPSD:
            tritonId = triton::arch::arm64::ID_INS_VCMPSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCMPSS:
            tritonId = triton::arch::arm64::ID_INS_VCMPSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTDQ2PD:
            tritonId = triton::arch::arm64::ID_INS_VCVTDQ2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTDQ2PS:
            tritonId = triton::arch::arm64::ID_INS_VCVTDQ2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPD2DQX:
            tritonId = triton::arch::arm64::ID_INS_VCVTPD2DQX;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPD2DQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTPD2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPD2PSX:
            tritonId = triton::arch::arm64::ID_INS_VCVTPD2PSX;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPD2PS:
            tritonId = triton::arch::arm64::ID_INS_VCVTPD2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPD2UDQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTPD2UDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPH2PS:
            tritonId = triton::arch::arm64::ID_INS_VCVTPH2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPS2DQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTPS2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPS2PD:
            tritonId = triton::arch::arm64::ID_INS_VCVTPS2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPS2PH:
            tritonId = triton::arch::arm64::ID_INS_VCVTPS2PH;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTPS2UDQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTPS2UDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSD2SI:
            tritonId = triton::arch::arm64::ID_INS_VCVTSD2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSD2USI:
            tritonId = triton::arch::arm64::ID_INS_VCVTSD2USI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSS2SI:
            tritonId = triton::arch::arm64::ID_INS_VCVTSS2SI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTSS2USI:
            tritonId = triton::arch::arm64::ID_INS_VCVTSS2USI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTPD2DQX:
            tritonId = triton::arch::arm64::ID_INS_VCVTTPD2DQX;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTPD2DQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTTPD2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTPD2UDQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTTPD2UDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTPS2DQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTTPS2DQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTTPS2UDQ:
            tritonId = triton::arch::arm64::ID_INS_VCVTTPS2UDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTUDQ2PD:
            tritonId = triton::arch::arm64::ID_INS_VCVTUDQ2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VCVTUDQ2PS:
            tritonId = triton::arch::arm64::ID_INS_VCVTUDQ2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDIVPD:
            tritonId = triton::arch::arm64::ID_INS_VDIVPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDIVPS:
            tritonId = triton::arch::arm64::ID_INS_VDIVPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDIVSD:
            tritonId = triton::arch::arm64::ID_INS_VDIVSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDIVSS:
            tritonId = triton::arch::arm64::ID_INS_VDIVSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDPPD:
            tritonId = triton::arch::arm64::ID_INS_VDPPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VDPPS:
            tritonId = triton::arch::arm64::ID_INS_VDPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VERR:
            tritonId = triton::arch::arm64::ID_INS_VERR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VERW:
            tritonId = triton::arch::arm64::ID_INS_VERW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTF128:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTF128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTF32X4:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTF32X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTF64X4:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTF64X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTI128:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTI128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTI32X4:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTI32X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTI64X4:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTI64X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VEXTRACTPS:
            tritonId = triton::arch::arm64::ID_INS_VEXTRACTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD132PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD132PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD213PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD213PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDPD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD231PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDPS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD231PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD213SD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD213SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD132SD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD132SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD231SD:
            tritonId = triton::arch::arm64::ID_INS_VFMADD231SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD213SS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD213SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD132SS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD132SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADD231SS:
            tritonId = triton::arch::arm64::ID_INS_VFMADD231SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB132PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB132PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB213PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB213PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB231PD:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMADDSUB231PS:
            tritonId = triton::arch::arm64::ID_INS_VFMADDSUB231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB132PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB132PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB213PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB213PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD132PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD132PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD213PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD213PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADDPD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD231PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADDPS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBADD231PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBADD231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB231PD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB231PS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBSD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB213SD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB213SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB132SD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB132SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB231SD:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB231SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUBSS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUBSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB213SS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB213SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB132SS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB132SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFMSUB231SS:
            tritonId = triton::arch::arm64::ID_INS_VFMSUB231SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD132PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD132PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD213PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD213PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADDPD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD231PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADDPS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD231PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADDSD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD213SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD213SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD132SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD132SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD231SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD231SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADDSS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD213SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD213SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD132SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD132SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMADD231SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMADD231SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB132PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB132PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB132PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB132PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB213PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB213PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB213PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB213PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB231PD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB231PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB231PS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB231PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUBSD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUBSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB213SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB213SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB132SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB132SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB231SD:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB231SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUBSS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUBSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB213SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB213SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB132SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB132SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFNMSUB231SS:
            tritonId = triton::arch::arm64::ID_INS_VFNMSUB231SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFRCZPD:
            tritonId = triton::arch::arm64::ID_INS_VFRCZPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFRCZPS:
            tritonId = triton::arch::arm64::ID_INS_VFRCZPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFRCZSD:
            tritonId = triton::arch::arm64::ID_INS_VFRCZSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VFRCZSS:
            tritonId = triton::arch::arm64::ID_INS_VFRCZSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VORPD:
            tritonId = triton::arch::arm64::ID_INS_VORPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VORPS:
            tritonId = triton::arch::arm64::ID_INS_VORPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VXORPD:
            tritonId = triton::arch::arm64::ID_INS_VXORPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VXORPS:
            tritonId = triton::arch::arm64::ID_INS_VXORPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERDPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERDPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF0DPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF0DPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF0DPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF0DPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF0QPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF0QPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF0QPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF0QPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF1DPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF1DPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF1DPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF1DPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF1QPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF1QPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERPF1QPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERPF1QPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERQPD:
            tritonId = triton::arch::arm64::ID_INS_VGATHERQPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VGATHERQPS:
            tritonId = triton::arch::arm64::ID_INS_VGATHERQPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VHADDPD:
            tritonId = triton::arch::arm64::ID_INS_VHADDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VHADDPS:
            tritonId = triton::arch::arm64::ID_INS_VHADDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VHSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VHSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VHSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VHSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTF128:
            tritonId = triton::arch::arm64::ID_INS_VINSERTF128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTF32X4:
            tritonId = triton::arch::arm64::ID_INS_VINSERTF32X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTF64X4:
            tritonId = triton::arch::arm64::ID_INS_VINSERTF64X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTI128:
            tritonId = triton::arch::arm64::ID_INS_VINSERTI128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTI32X4:
            tritonId = triton::arch::arm64::ID_INS_VINSERTI32X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTI64X4:
            tritonId = triton::arch::arm64::ID_INS_VINSERTI64X4;
            break;

          case triton::extlibs::capstone::ARM64_INS_VINSERTPS:
            tritonId = triton::arch::arm64::ID_INS_VINSERTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VLDDQU:
            tritonId = triton::arch::arm64::ID_INS_VLDDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_VLDMXCSR:
            tritonId = triton::arch::arm64::ID_INS_VLDMXCSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMASKMOVDQU:
            tritonId = triton::arch::arm64::ID_INS_VMASKMOVDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMASKMOVPD:
            tritonId = triton::arch::arm64::ID_INS_VMASKMOVPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMASKMOVPS:
            tritonId = triton::arch::arm64::ID_INS_VMASKMOVPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMAXPD:
            tritonId = triton::arch::arm64::ID_INS_VMAXPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMAXPS:
            tritonId = triton::arch::arm64::ID_INS_VMAXPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMAXSD:
            tritonId = triton::arch::arm64::ID_INS_VMAXSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMAXSS:
            tritonId = triton::arch::arm64::ID_INS_VMAXSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMCALL:
            tritonId = triton::arch::arm64::ID_INS_VMCALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMCLEAR:
            tritonId = triton::arch::arm64::ID_INS_VMCLEAR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMFUNC:
            tritonId = triton::arch::arm64::ID_INS_VMFUNC;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMINPD:
            tritonId = triton::arch::arm64::ID_INS_VMINPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMINPS:
            tritonId = triton::arch::arm64::ID_INS_VMINPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMINSD:
            tritonId = triton::arch::arm64::ID_INS_VMINSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMINSS:
            tritonId = triton::arch::arm64::ID_INS_VMINSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMLAUNCH:
            tritonId = triton::arch::arm64::ID_INS_VMLAUNCH;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMLOAD:
            tritonId = triton::arch::arm64::ID_INS_VMLOAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMMCALL:
            tritonId = triton::arch::arm64::ID_INS_VMMCALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVQ:
            tritonId = triton::arch::arm64::ID_INS_VMOVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDDUP:
            tritonId = triton::arch::arm64::ID_INS_VMOVDDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVD:
            tritonId = triton::arch::arm64::ID_INS_VMOVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQA32:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQA32;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQA64:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQA64;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQA:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQA;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQU16:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQU16;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQU32:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQU32;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQU64:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQU64;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQU8:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQU8;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVDQU:
            tritonId = triton::arch::arm64::ID_INS_VMOVDQU;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVHLPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVHLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVHPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVHPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVHPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVLHPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVLHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVLPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVLPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVLPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVMSKPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVMSKPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVMSKPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVMSKPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVNTDQA:
            tritonId = triton::arch::arm64::ID_INS_VMOVNTDQA;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVNTDQ:
            tritonId = triton::arch::arm64::ID_INS_VMOVNTDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVNTPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVNTPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVNTPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVNTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVSD:
            tritonId = triton::arch::arm64::ID_INS_VMOVSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVSHDUP:
            tritonId = triton::arch::arm64::ID_INS_VMOVSHDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVSLDUP:
            tritonId = triton::arch::arm64::ID_INS_VMOVSLDUP;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVSS:
            tritonId = triton::arch::arm64::ID_INS_VMOVSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVUPD:
            tritonId = triton::arch::arm64::ID_INS_VMOVUPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMOVUPS:
            tritonId = triton::arch::arm64::ID_INS_VMOVUPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMPSADBW:
            tritonId = triton::arch::arm64::ID_INS_VMPSADBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMPTRLD:
            tritonId = triton::arch::arm64::ID_INS_VMPTRLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMPTRST:
            tritonId = triton::arch::arm64::ID_INS_VMPTRST;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMREAD:
            tritonId = triton::arch::arm64::ID_INS_VMREAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMRESUME:
            tritonId = triton::arch::arm64::ID_INS_VMRESUME;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMRUN:
            tritonId = triton::arch::arm64::ID_INS_VMRUN;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMSAVE:
            tritonId = triton::arch::arm64::ID_INS_VMSAVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMULPD:
            tritonId = triton::arch::arm64::ID_INS_VMULPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMULPS:
            tritonId = triton::arch::arm64::ID_INS_VMULPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMULSD:
            tritonId = triton::arch::arm64::ID_INS_VMULSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMULSS:
            tritonId = triton::arch::arm64::ID_INS_VMULSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMWRITE:
            tritonId = triton::arch::arm64::ID_INS_VMWRITE;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMXOFF:
            tritonId = triton::arch::arm64::ID_INS_VMXOFF;
            break;

          case triton::extlibs::capstone::ARM64_INS_VMXON:
            tritonId = triton::arch::arm64::ID_INS_VMXON;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPABSB:
            tritonId = triton::arch::arm64::ID_INS_VPABSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPABSD:
            tritonId = triton::arch::arm64::ID_INS_VPABSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPABSQ:
            tritonId = triton::arch::arm64::ID_INS_VPABSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPABSW:
            tritonId = triton::arch::arm64::ID_INS_VPABSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPACKSSDW:
            tritonId = triton::arch::arm64::ID_INS_VPACKSSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPACKSSWB:
            tritonId = triton::arch::arm64::ID_INS_VPACKSSWB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPACKUSDW:
            tritonId = triton::arch::arm64::ID_INS_VPACKUSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPACKUSWB:
            tritonId = triton::arch::arm64::ID_INS_VPACKUSWB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDB:
            tritonId = triton::arch::arm64::ID_INS_VPADDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDD:
            tritonId = triton::arch::arm64::ID_INS_VPADDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDQ:
            tritonId = triton::arch::arm64::ID_INS_VPADDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDSB:
            tritonId = triton::arch::arm64::ID_INS_VPADDSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDSW:
            tritonId = triton::arch::arm64::ID_INS_VPADDSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDUSB:
            tritonId = triton::arch::arm64::ID_INS_VPADDUSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDUSW:
            tritonId = triton::arch::arm64::ID_INS_VPADDUSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPADDW:
            tritonId = triton::arch::arm64::ID_INS_VPADDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPALIGNR:
            tritonId = triton::arch::arm64::ID_INS_VPALIGNR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPANDD:
            tritonId = triton::arch::arm64::ID_INS_VPANDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPANDND:
            tritonId = triton::arch::arm64::ID_INS_VPANDND;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPANDNQ:
            tritonId = triton::arch::arm64::ID_INS_VPANDNQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPANDN:
            tritonId = triton::arch::arm64::ID_INS_VPANDN;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPANDQ:
            tritonId = triton::arch::arm64::ID_INS_VPANDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPAND:
            tritonId = triton::arch::arm64::ID_INS_VPAND;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPAVGB:
            tritonId = triton::arch::arm64::ID_INS_VPAVGB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPAVGW:
            tritonId = triton::arch::arm64::ID_INS_VPAVGW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBLENDD:
            tritonId = triton::arch::arm64::ID_INS_VPBLENDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBLENDMD:
            tritonId = triton::arch::arm64::ID_INS_VPBLENDMD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBLENDMQ:
            tritonId = triton::arch::arm64::ID_INS_VPBLENDMQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBLENDVB:
            tritonId = triton::arch::arm64::ID_INS_VPBLENDVB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBLENDW:
            tritonId = triton::arch::arm64::ID_INS_VPBLENDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTB:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTD:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTMB2Q:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTMB2Q;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTMW2D:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTMW2D;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTQ:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPBROADCASTW:
            tritonId = triton::arch::arm64::ID_INS_VPBROADCASTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCLMULQDQ:
            tritonId = triton::arch::arm64::ID_INS_VPCLMULQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMOV:
            tritonId = triton::arch::arm64::ID_INS_VPCMOV;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMP:
            tritonId = triton::arch::arm64::ID_INS_VPCMP;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPD:
            tritonId = triton::arch::arm64::ID_INS_VPCMPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPEQB:
            tritonId = triton::arch::arm64::ID_INS_VPCMPEQB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPEQD:
            tritonId = triton::arch::arm64::ID_INS_VPCMPEQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPEQQ:
            tritonId = triton::arch::arm64::ID_INS_VPCMPEQQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPEQW:
            tritonId = triton::arch::arm64::ID_INS_VPCMPEQW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPESTRI:
            tritonId = triton::arch::arm64::ID_INS_VPCMPESTRI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPESTRM:
            tritonId = triton::arch::arm64::ID_INS_VPCMPESTRM;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPGTB:
            tritonId = triton::arch::arm64::ID_INS_VPCMPGTB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPGTD:
            tritonId = triton::arch::arm64::ID_INS_VPCMPGTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPGTQ:
            tritonId = triton::arch::arm64::ID_INS_VPCMPGTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPGTW:
            tritonId = triton::arch::arm64::ID_INS_VPCMPGTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPISTRI:
            tritonId = triton::arch::arm64::ID_INS_VPCMPISTRI;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPISTRM:
            tritonId = triton::arch::arm64::ID_INS_VPCMPISTRM;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPQ:
            tritonId = triton::arch::arm64::ID_INS_VPCMPQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPUD:
            tritonId = triton::arch::arm64::ID_INS_VPCMPUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCMPUQ:
            tritonId = triton::arch::arm64::ID_INS_VPCMPUQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMB:
            tritonId = triton::arch::arm64::ID_INS_VPCOMB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMD:
            tritonId = triton::arch::arm64::ID_INS_VPCOMD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMQ:
            tritonId = triton::arch::arm64::ID_INS_VPCOMQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMUB:
            tritonId = triton::arch::arm64::ID_INS_VPCOMUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMUD:
            tritonId = triton::arch::arm64::ID_INS_VPCOMUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMUQ:
            tritonId = triton::arch::arm64::ID_INS_VPCOMUQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMUW:
            tritonId = triton::arch::arm64::ID_INS_VPCOMUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCOMW:
            tritonId = triton::arch::arm64::ID_INS_VPCOMW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCONFLICTD:
            tritonId = triton::arch::arm64::ID_INS_VPCONFLICTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPCONFLICTQ:
            tritonId = triton::arch::arm64::ID_INS_VPCONFLICTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERM2F128:
            tritonId = triton::arch::arm64::ID_INS_VPERM2F128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERM2I128:
            tritonId = triton::arch::arm64::ID_INS_VPERM2I128;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMD:
            tritonId = triton::arch::arm64::ID_INS_VPERMD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMI2D:
            tritonId = triton::arch::arm64::ID_INS_VPERMI2D;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMI2PD:
            tritonId = triton::arch::arm64::ID_INS_VPERMI2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMI2PS:
            tritonId = triton::arch::arm64::ID_INS_VPERMI2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMI2Q:
            tritonId = triton::arch::arm64::ID_INS_VPERMI2Q;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMIL2PD:
            tritonId = triton::arch::arm64::ID_INS_VPERMIL2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMIL2PS:
            tritonId = triton::arch::arm64::ID_INS_VPERMIL2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMILPD:
            tritonId = triton::arch::arm64::ID_INS_VPERMILPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMILPS:
            tritonId = triton::arch::arm64::ID_INS_VPERMILPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMPD:
            tritonId = triton::arch::arm64::ID_INS_VPERMPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMPS:
            tritonId = triton::arch::arm64::ID_INS_VPERMPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMQ:
            tritonId = triton::arch::arm64::ID_INS_VPERMQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMT2D:
            tritonId = triton::arch::arm64::ID_INS_VPERMT2D;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMT2PD:
            tritonId = triton::arch::arm64::ID_INS_VPERMT2PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMT2PS:
            tritonId = triton::arch::arm64::ID_INS_VPERMT2PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPERMT2Q:
            tritonId = triton::arch::arm64::ID_INS_VPERMT2Q;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPEXTRB:
            tritonId = triton::arch::arm64::ID_INS_VPEXTRB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPEXTRD:
            tritonId = triton::arch::arm64::ID_INS_VPEXTRD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPEXTRQ:
            tritonId = triton::arch::arm64::ID_INS_VPEXTRQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPEXTRW:
            tritonId = triton::arch::arm64::ID_INS_VPEXTRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPGATHERDD:
            tritonId = triton::arch::arm64::ID_INS_VPGATHERDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPGATHERDQ:
            tritonId = triton::arch::arm64::ID_INS_VPGATHERDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPGATHERQD:
            tritonId = triton::arch::arm64::ID_INS_VPGATHERQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPGATHERQQ:
            tritonId = triton::arch::arm64::ID_INS_VPGATHERQQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDBD:
            tritonId = triton::arch::arm64::ID_INS_VPHADDBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDBQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDBW:
            tritonId = triton::arch::arm64::ID_INS_VPHADDBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDDQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDD:
            tritonId = triton::arch::arm64::ID_INS_VPHADDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDSW:
            tritonId = triton::arch::arm64::ID_INS_VPHADDSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUBD:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUBQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUBW:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUDQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUWD:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDUWQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDUWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDWD:
            tritonId = triton::arch::arm64::ID_INS_VPHADDWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDWQ:
            tritonId = triton::arch::arm64::ID_INS_VPHADDWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHADDW:
            tritonId = triton::arch::arm64::ID_INS_VPHADDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHMINPOSUW:
            tritonId = triton::arch::arm64::ID_INS_VPHMINPOSUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBBW:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBDQ:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBD:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBSW:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBWD:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPHSUBW:
            tritonId = triton::arch::arm64::ID_INS_VPHSUBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPINSRB:
            tritonId = triton::arch::arm64::ID_INS_VPINSRB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPINSRD:
            tritonId = triton::arch::arm64::ID_INS_VPINSRD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPINSRQ:
            tritonId = triton::arch::arm64::ID_INS_VPINSRQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPINSRW:
            tritonId = triton::arch::arm64::ID_INS_VPINSRW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPLZCNTD:
            tritonId = triton::arch::arm64::ID_INS_VPLZCNTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPLZCNTQ:
            tritonId = triton::arch::arm64::ID_INS_VPLZCNTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSDD:
            tritonId = triton::arch::arm64::ID_INS_VPMACSDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSDQH:
            tritonId = triton::arch::arm64::ID_INS_VPMACSDQH;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSDQL:
            tritonId = triton::arch::arm64::ID_INS_VPMACSDQL;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSSDD:
            tritonId = triton::arch::arm64::ID_INS_VPMACSSDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSSDQH:
            tritonId = triton::arch::arm64::ID_INS_VPMACSSDQH;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSSDQL:
            tritonId = triton::arch::arm64::ID_INS_VPMACSSDQL;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSSWD:
            tritonId = triton::arch::arm64::ID_INS_VPMACSSWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSSWW:
            tritonId = triton::arch::arm64::ID_INS_VPMACSSWW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSWD:
            tritonId = triton::arch::arm64::ID_INS_VPMACSWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMACSWW:
            tritonId = triton::arch::arm64::ID_INS_VPMACSWW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMADCSSWD:
            tritonId = triton::arch::arm64::ID_INS_VPMADCSSWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMADCSWD:
            tritonId = triton::arch::arm64::ID_INS_VPMADCSWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMADDUBSW:
            tritonId = triton::arch::arm64::ID_INS_VPMADDUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMADDWD:
            tritonId = triton::arch::arm64::ID_INS_VPMADDWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMASKMOVD:
            tritonId = triton::arch::arm64::ID_INS_VPMASKMOVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMASKMOVQ:
            tritonId = triton::arch::arm64::ID_INS_VPMASKMOVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXSB:
            tritonId = triton::arch::arm64::ID_INS_VPMAXSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXSD:
            tritonId = triton::arch::arm64::ID_INS_VPMAXSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXSQ:
            tritonId = triton::arch::arm64::ID_INS_VPMAXSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXSW:
            tritonId = triton::arch::arm64::ID_INS_VPMAXSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXUB:
            tritonId = triton::arch::arm64::ID_INS_VPMAXUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXUD:
            tritonId = triton::arch::arm64::ID_INS_VPMAXUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXUQ:
            tritonId = triton::arch::arm64::ID_INS_VPMAXUQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMAXUW:
            tritonId = triton::arch::arm64::ID_INS_VPMAXUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINSB:
            tritonId = triton::arch::arm64::ID_INS_VPMINSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINSD:
            tritonId = triton::arch::arm64::ID_INS_VPMINSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINSQ:
            tritonId = triton::arch::arm64::ID_INS_VPMINSQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINSW:
            tritonId = triton::arch::arm64::ID_INS_VPMINSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINUB:
            tritonId = triton::arch::arm64::ID_INS_VPMINUB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINUD:
            tritonId = triton::arch::arm64::ID_INS_VPMINUD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINUQ:
            tritonId = triton::arch::arm64::ID_INS_VPMINUQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMINUW:
            tritonId = triton::arch::arm64::ID_INS_VPMINUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVDB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVDW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVMSKB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVMSKB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVQB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVQB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVQD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVQW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVQW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSDB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSDW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSQB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSQB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSQD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSQW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSQW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXBD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXBQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXBW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXDQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXWD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVSXWQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVSXWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVUSDB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVUSDB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVUSDW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVUSDW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVUSQB:
            tritonId = triton::arch::arm64::ID_INS_VPMOVUSQB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVUSQD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVUSQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVUSQW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVUSQW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXBD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXBQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXBW:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXDQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXWD:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMOVZXWQ:
            tritonId = triton::arch::arm64::ID_INS_VPMOVZXWQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULDQ:
            tritonId = triton::arch::arm64::ID_INS_VPMULDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULHRSW:
            tritonId = triton::arch::arm64::ID_INS_VPMULHRSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULHUW:
            tritonId = triton::arch::arm64::ID_INS_VPMULHUW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULHW:
            tritonId = triton::arch::arm64::ID_INS_VPMULHW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULLD:
            tritonId = triton::arch::arm64::ID_INS_VPMULLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULLW:
            tritonId = triton::arch::arm64::ID_INS_VPMULLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPMULUDQ:
            tritonId = triton::arch::arm64::ID_INS_VPMULUDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPORD:
            tritonId = triton::arch::arm64::ID_INS_VPORD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPORQ:
            tritonId = triton::arch::arm64::ID_INS_VPORQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPOR:
            tritonId = triton::arch::arm64::ID_INS_VPOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPPERM:
            tritonId = triton::arch::arm64::ID_INS_VPPERM;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPROTB:
            tritonId = triton::arch::arm64::ID_INS_VPROTB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPROTD:
            tritonId = triton::arch::arm64::ID_INS_VPROTD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPROTQ:
            tritonId = triton::arch::arm64::ID_INS_VPROTQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPROTW:
            tritonId = triton::arch::arm64::ID_INS_VPROTW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSADBW:
            tritonId = triton::arch::arm64::ID_INS_VPSADBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSCATTERDD:
            tritonId = triton::arch::arm64::ID_INS_VPSCATTERDD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSCATTERDQ:
            tritonId = triton::arch::arm64::ID_INS_VPSCATTERDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSCATTERQD:
            tritonId = triton::arch::arm64::ID_INS_VPSCATTERQD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSCATTERQQ:
            tritonId = triton::arch::arm64::ID_INS_VPSCATTERQQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHAB:
            tritonId = triton::arch::arm64::ID_INS_VPSHAB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHAD:
            tritonId = triton::arch::arm64::ID_INS_VPSHAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHAQ:
            tritonId = triton::arch::arm64::ID_INS_VPSHAQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHAW:
            tritonId = triton::arch::arm64::ID_INS_VPSHAW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHLB:
            tritonId = triton::arch::arm64::ID_INS_VPSHLB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHLD:
            tritonId = triton::arch::arm64::ID_INS_VPSHLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHLQ:
            tritonId = triton::arch::arm64::ID_INS_VPSHLQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHLW:
            tritonId = triton::arch::arm64::ID_INS_VPSHLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHUFB:
            tritonId = triton::arch::arm64::ID_INS_VPSHUFB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHUFD:
            tritonId = triton::arch::arm64::ID_INS_VPSHUFD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHUFHW:
            tritonId = triton::arch::arm64::ID_INS_VPSHUFHW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSHUFLW:
            tritonId = triton::arch::arm64::ID_INS_VPSHUFLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSIGNB:
            tritonId = triton::arch::arm64::ID_INS_VPSIGNB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSIGND:
            tritonId = triton::arch::arm64::ID_INS_VPSIGND;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSIGNW:
            tritonId = triton::arch::arm64::ID_INS_VPSIGNW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLDQ:
            tritonId = triton::arch::arm64::ID_INS_VPSLLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLD:
            tritonId = triton::arch::arm64::ID_INS_VPSLLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLQ:
            tritonId = triton::arch::arm64::ID_INS_VPSLLQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLVD:
            tritonId = triton::arch::arm64::ID_INS_VPSLLVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLVQ:
            tritonId = triton::arch::arm64::ID_INS_VPSLLVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSLLW:
            tritonId = triton::arch::arm64::ID_INS_VPSLLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRAD:
            tritonId = triton::arch::arm64::ID_INS_VPSRAD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRAQ:
            tritonId = triton::arch::arm64::ID_INS_VPSRAQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRAVD:
            tritonId = triton::arch::arm64::ID_INS_VPSRAVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRAVQ:
            tritonId = triton::arch::arm64::ID_INS_VPSRAVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRAW:
            tritonId = triton::arch::arm64::ID_INS_VPSRAW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLDQ:
            tritonId = triton::arch::arm64::ID_INS_VPSRLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLD:
            tritonId = triton::arch::arm64::ID_INS_VPSRLD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLQ:
            tritonId = triton::arch::arm64::ID_INS_VPSRLQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLVD:
            tritonId = triton::arch::arm64::ID_INS_VPSRLVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLVQ:
            tritonId = triton::arch::arm64::ID_INS_VPSRLVQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSRLW:
            tritonId = triton::arch::arm64::ID_INS_VPSRLW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBB:
            tritonId = triton::arch::arm64::ID_INS_VPSUBB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBD:
            tritonId = triton::arch::arm64::ID_INS_VPSUBD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBQ:
            tritonId = triton::arch::arm64::ID_INS_VPSUBQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBSB:
            tritonId = triton::arch::arm64::ID_INS_VPSUBSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBSW:
            tritonId = triton::arch::arm64::ID_INS_VPSUBSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBUSB:
            tritonId = triton::arch::arm64::ID_INS_VPSUBUSB;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBUSW:
            tritonId = triton::arch::arm64::ID_INS_VPSUBUSW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPSUBW:
            tritonId = triton::arch::arm64::ID_INS_VPSUBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPTESTMD:
            tritonId = triton::arch::arm64::ID_INS_VPTESTMD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPTESTMQ:
            tritonId = triton::arch::arm64::ID_INS_VPTESTMQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPTESTNMD:
            tritonId = triton::arch::arm64::ID_INS_VPTESTNMD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPTESTNMQ:
            tritonId = triton::arch::arm64::ID_INS_VPTESTNMQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPTEST:
            tritonId = triton::arch::arm64::ID_INS_VPTEST;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKHBW:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKHBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKHDQ:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKHDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKHQDQ:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKHQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKHWD:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKHWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKLBW:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKLBW;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKLDQ:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKLDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKLQDQ:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKLQDQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPUNPCKLWD:
            tritonId = triton::arch::arm64::ID_INS_VPUNPCKLWD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPXORD:
            tritonId = triton::arch::arm64::ID_INS_VPXORD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPXORQ:
            tritonId = triton::arch::arm64::ID_INS_VPXORQ;
            break;

          case triton::extlibs::capstone::ARM64_INS_VPXOR:
            tritonId = triton::arch::arm64::ID_INS_VPXOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP14PD:
            tritonId = triton::arch::arm64::ID_INS_VRCP14PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP14PS:
            tritonId = triton::arch::arm64::ID_INS_VRCP14PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP14SD:
            tritonId = triton::arch::arm64::ID_INS_VRCP14SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP14SS:
            tritonId = triton::arch::arm64::ID_INS_VRCP14SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP28PD:
            tritonId = triton::arch::arm64::ID_INS_VRCP28PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP28PS:
            tritonId = triton::arch::arm64::ID_INS_VRCP28PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP28SD:
            tritonId = triton::arch::arm64::ID_INS_VRCP28SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCP28SS:
            tritonId = triton::arch::arm64::ID_INS_VRCP28SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCPPS:
            tritonId = triton::arch::arm64::ID_INS_VRCPPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRCPSS:
            tritonId = triton::arch::arm64::ID_INS_VRCPSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRNDSCALEPD:
            tritonId = triton::arch::arm64::ID_INS_VRNDSCALEPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRNDSCALEPS:
            tritonId = triton::arch::arm64::ID_INS_VRNDSCALEPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRNDSCALESD:
            tritonId = triton::arch::arm64::ID_INS_VRNDSCALESD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRNDSCALESS:
            tritonId = triton::arch::arm64::ID_INS_VRNDSCALESS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VROUNDPD:
            tritonId = triton::arch::arm64::ID_INS_VROUNDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VROUNDPS:
            tritonId = triton::arch::arm64::ID_INS_VROUNDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VROUNDSD:
            tritonId = triton::arch::arm64::ID_INS_VROUNDSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VROUNDSS:
            tritonId = triton::arch::arm64::ID_INS_VROUNDSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT14PD:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT14PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT14PS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT14PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT14SD:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT14SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT14SS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT14SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT28PD:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT28PD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT28PS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT28PS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT28SD:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT28SD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRT28SS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRT28SS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRTPS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VRSQRTSS:
            tritonId = triton::arch::arm64::ID_INS_VRSQRTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERDPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERDPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERDPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERDPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF0DPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF0DPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF0DPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF0DPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF0QPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF0QPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF0QPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF0QPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF1DPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF1DPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF1DPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF1DPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF1QPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF1QPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERPF1QPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERPF1QPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERQPD:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERQPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSCATTERQPS:
            tritonId = triton::arch::arm64::ID_INS_VSCATTERQPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSHUFPD:
            tritonId = triton::arch::arm64::ID_INS_VSHUFPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSHUFPS:
            tritonId = triton::arch::arm64::ID_INS_VSHUFPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSQRTPD:
            tritonId = triton::arch::arm64::ID_INS_VSQRTPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSQRTPS:
            tritonId = triton::arch::arm64::ID_INS_VSQRTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSQRTSD:
            tritonId = triton::arch::arm64::ID_INS_VSQRTSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSQRTSS:
            tritonId = triton::arch::arm64::ID_INS_VSQRTSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSTMXCSR:
            tritonId = triton::arch::arm64::ID_INS_VSTMXCSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSUBPD:
            tritonId = triton::arch::arm64::ID_INS_VSUBPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSUBPS:
            tritonId = triton::arch::arm64::ID_INS_VSUBPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSUBSD:
            tritonId = triton::arch::arm64::ID_INS_VSUBSD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VSUBSS:
            tritonId = triton::arch::arm64::ID_INS_VSUBSS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VTESTPD:
            tritonId = triton::arch::arm64::ID_INS_VTESTPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VTESTPS:
            tritonId = triton::arch::arm64::ID_INS_VTESTPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUNPCKHPD:
            tritonId = triton::arch::arm64::ID_INS_VUNPCKHPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUNPCKHPS:
            tritonId = triton::arch::arm64::ID_INS_VUNPCKHPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUNPCKLPD:
            tritonId = triton::arch::arm64::ID_INS_VUNPCKLPD;
            break;

          case triton::extlibs::capstone::ARM64_INS_VUNPCKLPS:
            tritonId = triton::arch::arm64::ID_INS_VUNPCKLPS;
            break;

          case triton::extlibs::capstone::ARM64_INS_VZEROALL:
            tritonId = triton::arch::arm64::ID_INS_VZEROALL;
            break;

          case triton::extlibs::capstone::ARM64_INS_VZEROUPPER:
            tritonId = triton::arch::arm64::ID_INS_VZEROUPPER;
            break;

          case triton::extlibs::capstone::ARM64_INS_WAIT:
            tritonId = triton::arch::arm64::ID_INS_WAIT;
            break;

          case triton::extlibs::capstone::ARM64_INS_WBINVD:
            tritonId = triton::arch::arm64::ID_INS_WBINVD;
            break;

          case triton::extlibs::capstone::ARM64_INS_WRFSBASE:
            tritonId = triton::arch::arm64::ID_INS_WRFSBASE;
            break;

          case triton::extlibs::capstone::ARM64_INS_WRGSBASE:
            tritonId = triton::arch::arm64::ID_INS_WRGSBASE;
            break;

          case triton::extlibs::capstone::ARM64_INS_WRMSR:
            tritonId = triton::arch::arm64::ID_INS_WRMSR;
            break;

          case triton::extlibs::capstone::ARM64_INS_XABORT:
            tritonId = triton::arch::arm64::ID_INS_XABORT;
            break;

          case triton::extlibs::capstone::ARM64_INS_XACQUIRE:
            tritonId = triton::arch::arm64::ID_INS_XACQUIRE;
            break;

          case triton::extlibs::capstone::ARM64_INS_XBEGIN:
            tritonId = triton::arch::arm64::ID_INS_XBEGIN;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCHG:
            tritonId = triton::arch::arm64::ID_INS_XCHG;
            break;

          case triton::extlibs::capstone::ARM64_INS_FXCH:
            tritonId = triton::arch::arm64::ID_INS_FXCH;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCRYPTCBC:
            tritonId = triton::arch::arm64::ID_INS_XCRYPTCBC;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCRYPTCFB:
            tritonId = triton::arch::arm64::ID_INS_XCRYPTCFB;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCRYPTCTR:
            tritonId = triton::arch::arm64::ID_INS_XCRYPTCTR;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCRYPTECB:
            tritonId = triton::arch::arm64::ID_INS_XCRYPTECB;
            break;

          case triton::extlibs::capstone::ARM64_INS_XCRYPTOFB:
            tritonId = triton::arch::arm64::ID_INS_XCRYPTOFB;
            break;

          case triton::extlibs::capstone::ARM64_INS_XEND:
            tritonId = triton::arch::arm64::ID_INS_XEND;
            break;

          case triton::extlibs::capstone::ARM64_INS_XGETBV:
            tritonId = triton::arch::arm64::ID_INS_XGETBV;
            break;

          case triton::extlibs::capstone::ARM64_INS_XLATB:
            tritonId = triton::arch::arm64::ID_INS_XLATB;
            break;

          case triton::extlibs::capstone::ARM64_INS_XRELEASE:
            tritonId = triton::arch::arm64::ID_INS_XRELEASE;
            break;

          case triton::extlibs::capstone::ARM64_INS_XRSTOR:
            tritonId = triton::arch::arm64::ID_INS_XRSTOR;
            break;

          case triton::extlibs::capstone::ARM64_INS_XRSTOR64:
            tritonId = triton::arch::arm64::ID_INS_XRSTOR64;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSAVE:
            tritonId = triton::arch::arm64::ID_INS_XSAVE;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSAVE64:
            tritonId = triton::arch::arm64::ID_INS_XSAVE64;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSAVEOPT:
            tritonId = triton::arch::arm64::ID_INS_XSAVEOPT;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSAVEOPT64:
            tritonId = triton::arch::arm64::ID_INS_XSAVEOPT64;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSETBV:
            tritonId = triton::arch::arm64::ID_INS_XSETBV;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSHA1:
            tritonId = triton::arch::arm64::ID_INS_XSHA1;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSHA256:
            tritonId = triton::arch::arm64::ID_INS_XSHA256;
            break;

          case triton::extlibs::capstone::ARM64_INS_XSTORE:
            tritonId = triton::arch::arm64::ID_INS_XSTORE;
            break;

          case triton::extlibs::capstone::ARM64_INS_XTEST:
            tritonId = triton::arch::arm64::ID_INS_XTEST;
            break;

          default:
            tritonId = triton::arch::arm64::ID_INST_INVALID;
            break;

        }
        return tritonId;
      }


      /* Converts a capstone's prefix id to a triton's prefix id */
      triton::uint32 capstonePrefixToTritonPrefix(triton::uint32 id) {
        triton::uint32 tritonId = triton::arch::arm64::ID_PREFIX_INVALID;

        if (triton::api.getArchitecture() == triton::arch::ARCH_INVALID)
          return tritonId;

        switch (id) {

          case triton::extlibs::capstone::ARM64_PREFIX_LOCK:
            tritonId = triton::arch::arm64::ID_PREFIX_LOCK;
            break;

          case triton::extlibs::capstone::ARM64_PREFIX_REP:
            tritonId = triton::arch::arm64::ID_PREFIX_REP;
            break;

          case triton::extlibs::capstone::ARM64_PREFIX_REPNE:
            tritonId = triton::arch::arm64::ID_PREFIX_REPNE;
            break;

          default:
            tritonId = triton::arch::arm64::ID_PREFIX_INVALID;
            break;

        }
        return tritonId;
      }

    }; /* arm64 namespace */
  }; /* arch namespace */
}; /* triton namespace */

