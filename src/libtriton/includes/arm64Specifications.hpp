//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_ARM64SPECIFICATIONS_H
#define TRITON_ARM64SPECIFICATIONS_H

#include "registerOperand.hpp"



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Architecture namespace
  namespace arch {
  /*!
   *  \ingroup triton
   *  \addtogroup arch
   *  @{
   */

    //! The arm64 namespace
    namespace arm64 {
    /*!
     *  \ingroup arch
     *  \addtogroup arm64
     *  @{
     */

      extern triton::arch::Register arm64_reg_invalid;

      extern triton::arch::Register arm64_reg_x0;
      extern triton::arch::Register arm64_reg_x1;
      extern triton::arch::Register arm64_reg_x2;
      extern triton::arch::Register arm64_reg_x3;
      extern triton::arch::Register arm64_reg_x4;
      extern triton::arch::Register arm64_reg_x5;
      extern triton::arch::Register arm64_reg_x6;
      extern triton::arch::Register arm64_reg_x7;
      extern triton::arch::Register arm64_reg_x8;
      extern triton::arch::Register arm64_reg_x9;
      extern triton::arch::Register arm64_reg_x10;
      extern triton::arch::Register arm64_reg_x11;
      extern triton::arch::Register arm64_reg_x12;
      extern triton::arch::Register arm64_reg_x13;
      extern triton::arch::Register arm64_reg_x14;
      extern triton::arch::Register arm64_reg_x15;
      extern triton::arch::Register arm64_reg_x16;
      extern triton::arch::Register arm64_reg_x17;
      extern triton::arch::Register arm64_reg_x18;
      extern triton::arch::Register arm64_reg_x19;
      extern triton::arch::Register arm64_reg_x20;
      extern triton::arch::Register arm64_reg_x21;
      extern triton::arch::Register arm64_reg_x22;
      extern triton::arch::Register arm64_reg_x23;
      extern triton::arch::Register arm64_reg_x24;
      extern triton::arch::Register arm64_reg_x25;
      extern triton::arch::Register arm64_reg_x26;
      extern triton::arch::Register arm64_reg_x27;
      extern triton::arch::Register arm64_reg_x28;
      extern triton::arch::Register arm64_reg_x29;
      extern triton::arch::Register arm64_reg_x30;


      //! Returns all information about the register from its ID.
      std::tuple<std::string, triton::uint32, triton::uint32, triton::uint32> registerIdToRegisterInformation(triton::uint32 reg);

      //! Converts a capstone's register id to a triton's register id.
      triton::uint32 capstoneRegisterToTritonRegister(triton::uint32 id);

      //! Converts a capstone's instruction id to a triton's instruction id.
      triton::uint32 capstoneInstructionToTritonInstruction(triton::uint32 id);

      //! Converts a capstone's prefix id to a triton's prefix id.
      triton::uint32 capstonePrefixToTritonPrefix(triton::uint32 id);


      //! The list of registers.
      enum registers_e {
        ID_REG_INVALID = 0, //!< invalid = 0

        /* GPR 64-bits */
        ID_REG_X0, //!< x0
        ID_REG_X1, //!< x1
        ID_REG_X2, //!< x2
        ID_REG_X3, //!< x3
        ID_REG_X4, //!< x4
        ID_REG_X5, //!< x5
        ID_REG_X6, //!< x6
        ID_REG_X7, //!< x7
        ID_REG_X8, //!< x8
        ID_REG_X9, //!< x9
        ID_REG_X10, //!< x10
        ID_REG_X11, //!< x11
        ID_REG_X12, //!< x12
        ID_REG_X13, //!< x13
        ID_REG_X14, //!< x14
        ID_REG_X15, //!< x15
        ID_REG_X16, //!< x16
        ID_REG_X17, //!< x17
        ID_REG_X18, //!< x18
        ID_REG_X19, //!< x19
        ID_REG_X20, //!< x20
        ID_REG_X21, //!< x21
        ID_REG_X22, //!< x22
        ID_REG_X23, //!< x23
        ID_REG_X24, //!< x24
        ID_REG_X25, //!< x25
        ID_REG_X26, //!< x26
        ID_REG_X27, //!< x27
        ID_REG_X28, //!< x28
        ID_REG_X29, //!< x29
        ID_REG_X30, //!< x30

        /* Must be the last item */
        ID_REG_LAST_ITEM //!< must be the last item
      };

      //! Global set of registers.
      extern triton::arch::Register* arm64_regs[ID_REG_LAST_ITEM];

      /*! \brief The list of prefixes.
       *
       *  \description
       *  Note that `REP` and `REPE` have the some opcode. The `REP`
       *  prefix becomes a `REPE` if the instruction modifies `ZF`.
       */
      enum prefix_e {
        ID_PREFIX_INVALID = 0,  //!< invalid
        ID_PREFIX_LOCK,         //!< LOCK
        ID_PREFIX_REP,          //!< REP
        ID_PREFIX_REPE,         //!< REPE
        ID_PREFIX_REPNE,        //!< REPNE

        /* Must be the last item */
        ID_PREFIX_LAST_ITEM     //!< must be the last item
      };

      //! The list of opcodes.
      enum instructions_e {
        ID_INST_INVALID = 0, //!< invalid

        ID_INS_AAA, //!< AAA

        /* Must be the last item */
        ID_INST_LAST_ITEM //!< must be the last item
      };

    /*! @} End of arm64 namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};


//! Temporary INVALID register.
#define TRITON_ARM64_REG_INVALID  triton::arch::arm64::arm64_reg_invalid
//! Temporary X0 register.
#define TRITON_ARM64_REG_X0       triton::arch::arm64::arm64_reg_x0
//! Temporary X1 register.
#define TRITON_ARM64_REG_X1       triton::arch::arm64::arm64_reg_x1
//! Temporary X2 register.
#define TRITON_ARM64_REG_X2       triton::arch::arm64::arm64_reg_x2
//! Temporary X3 register.
#define TRITON_ARM64_REG_X3       triton::arch::arm64::arm64_reg_x3
//! Temporary X4 register.
#define TRITON_ARM64_REG_X4       triton::arch::arm64::arm64_reg_x4
//! Temporary X5 register.
#define TRITON_ARM64_REG_X5       triton::arch::arm64::arm64_reg_x5
//! Temporary X6 register.
#define TRITON_ARM64_REG_X6       triton::arch::arm64::arm64_reg_x6
//! Temporary X7 register.
#define TRITON_ARM64_REG_X7       triton::arch::arm64::arm64_reg_x7
//! Temporary X8 register.
#define TRITON_ARM64_REG_X8       triton::arch::arm64::arm64_reg_x8
//! Temporary X9 register.
#define TRITON_ARM64_REG_X9       triton::arch::arm64::arm64_reg_x9
//! Temporary X10 register.
#define TRITON_ARM64_REG_X10      triton::arch::arm64::arm64_reg_x10
//! Temporary X11 register.
#define TRITON_ARM64_REG_X11      triton::arch::arm64::arm64_reg_x11
//! Temporary X12 register.
#define TRITON_ARM64_REG_X12      triton::arch::arm64::arm64_reg_x12
//! Temporary X13 register.
#define TRITON_ARM64_REG_X13      triton::arch::arm64::arm64_reg_x13
//! Temporary X14 register.
#define TRITON_ARM64_REG_X14      triton::arch::arm64::arm64_reg_x14
//! Temporary X15 register.
#define TRITON_ARM64_REG_X15      triton::arch::arm64::arm64_reg_x15
//! Temporary X16 register.
#define TRITON_ARM64_REG_X16      triton::arch::arm64::arm64_reg_x16
//! Temporary X17 register.
#define TRITON_ARM64_REG_X17      triton::arch::arm64::arm64_reg_x17
//! Temporary X18 register.
#define TRITON_ARM64_REG_X18      triton::arch::arm64::arm64_reg_x18
//! Temporary X19 register.
#define TRITON_ARM64_REG_X19      triton::arch::arm64::arm64_reg_x19
//! Temporary X20 register.
#define TRITON_ARM64_REG_X20      triton::arch::arm64::arm64_reg_x20
//! Temporary X21 register.
#define TRITON_ARM64_REG_X21      triton::arch::arm64::arm64_reg_x21
//! Temporary X22 register.
#define TRITON_ARM64_REG_X22      triton::arch::arm64::arm64_reg_x22
//! Temporary X23 register.
#define TRITON_ARM64_REG_X23      triton::arch::arm64::arm64_reg_x23
//! Temporary X24 register.
#define TRITON_ARM64_REG_X24      triton::arch::arm64::arm64_reg_x24
//! Temporary X25 register.
#define TRITON_ARM64_REG_X25      triton::arch::arm64::arm64_reg_x25
//! Temporary X26 register.
#define TRITON_ARM64_REG_X26      triton::arch::arm64::arm64_reg_x26
//! Temporary X27 register.
#define TRITON_ARM64_REG_X27      triton::arch::arm64::arm64_reg_x27
//! Temporary X28 register.
#define TRITON_ARM64_REG_X28      triton::arch::arm64::arm64_reg_x28
//! Temporary X29 register.
#define TRITON_ARM64_REG_X29      triton::arch::arm64::arm64_reg_x29
//! Temporary X30 register.
#define TRITON_ARM64_REG_X30      triton::arch::arm64::arm64_reg_x30

#endif /* TRITON_ARM64SPECIFICATIONS_H */
