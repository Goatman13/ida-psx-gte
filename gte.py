import idaapi
import ida_ida
import ida_allins
import ida_idp
import ida_bytes
import ida_ua

ITYPE_START = ida_idp.CUSTOM_INSN_ITYPE + 0x100
MNEM_WIDTH = 13

class GTE_disassemble(idaapi.IDP_Hooks):

	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)

		class idef:
			def __init__(self, opcode, name, cmt):
				self.opcode = opcode
				self.name = name
				self.cmt = cmt

		self.itable = [
			# Coprocessor Calculation Instructions
			idef(0x01,  "RTPS",  "Perspective Transformation single"),
			idef(0x06,  "NCLIP", "Normal clipping"),
			idef(0x0C,  "OP",    "Outer product of 2 vectors"),
			idef(0x10,  "DPCS",  "Depth Cueing single"),
			idef(0x11,  "INTPL", "Interpolation of a vector and far color vector"),
			idef(0x12 , "MVMVA", "Multiply vector by matrix and add vector (see below)"), #sf handled in different part.
			idef(0x13,  "NCDS",  "Normal color depth cue single vector"),
			idef(0x14,  "CDP",   "Color Depth Que"),
			idef(0x16,  "NCDT",  "Normal color depth cue triple vectors"),
			idef(0x1B,  "NCCS",  "Normal Color Color single vector"),
			idef(0x1C,  "CC",    "Color Color"),
			idef(0x1E,  "NCS",   "Normal color single"),
			idef(0x20,  "NCT",   "Normal color triple"),
			idef(0x28,  "SQR",   "Square of vector IR"),
			idef(0x29,  "DCPL",  "Depth Cue Color light"),
			idef(0x2A,  "DPCT",  "Depth Cueing triple (should be fake=08h, but isn't)"),
			idef(0x2D,  "AVSZ3", "Average of three Z values"),
			idef(0x2E,  "AVSZ4", "Average of four Z values"),
			idef(0x30,  "RTPT",  "Perspective Transformation triple"),
			idef(0x3D,  "GPF",   "General purpose interpolation"),
			idef(0x3E,  "GPL",   "General purpose interpolation with base"),
			idef(0x3F,  "NCCT",  "Normal Color Color triple vector"),
		]
		
		self.CFC2_ITABLE_ID  = ida_allins.MIPS_cfc2
		self.CTC2_ITABLE_ID  = ida_allins.MIPS_ctc2
		self.MFC2_ITABLE_ID  = ida_allins.MIPS_mfc2
		self.MTC2_ITABLE_ID  = ida_allins.MIPS_mtc2
		self.LWC2_ITABLE_ID  = ida_allins.MIPS_lwc2
		self.SWC2_ITABLE_ID  = ida_allins.MIPS_swc2

		self.DATA_REG = 0
		self.CTRL_REG = 1

		for entry in self.itable:
			entry.name = entry.name.lower()

	def ev_ana_insn(self, insn):

		dword = ida_bytes.get_wide_dword(insn.ea)

		if (dword >> 0x19 == 0x25):

			opcode = dword & 0x3F

			pos = 0
			found = False
			index = 0
			for i in range(pos, len(self.itable)):
				if (self.itable[i].opcode == opcode):
					found = True
					index = i
					break

			if (not found):
				return 0
		
			insn.itype = ITYPE_START + index
			insn.Op1.type = ida_ua.o_void
			insn.size = 4

		return insn.size

	def ev_get_autocmt(self, insn):
		if (insn.itype >= ITYPE_START and insn.itype < ITYPE_START + len(self.itable)):
			print(self.itable[insn.itype-ITYPE_START].cmt)
			return self.itable[insn.itype-ITYPE_START].cmt
		#return 0

	def ev_emu_insn(self, insn):
		if (insn.itype >= ITYPE_START and insn.itype < ITYPE_START + len(self.itable)):
			insn.add_cref(insn.ea + insn.size, 0, 21); # 21 Ordinary flow
			return 1
		return 0

	def get_register(self, op, ctx):

		ctrl_regs = ["R11R12", "R13R21", "R22R23", "R31R32", "R33", "TRX", "TRY", "TRZ",
					"L11L12", "L13L21", "L22L23", "L31L32", "L33", "RBK", "BBK", "GBK",
					"LR1LR2", "LR3LG1", "LG2LG3", "LB1LB2", "LB3", "RFC", "GFC", "BFC",
					"OFX", "OFY", "H", "DQA", "DQB", "ZSF3", "ZSF4", "FLAG"]
		
		data_regs = ["VXY0", "VZ0", "VXY1", "VZ1", "VXY2", "VZ2" ,"RGBC" ,"OTZ" ,"IR0", "IR1",
					"IR2", "IR3", "SXY0", "SXY1", "SXY2", "SXYP", "SZ0", "SZ1", "SZ2", "SZ3",
					"RGB0", "RGB1", "RGB2", "(RES1)", "MAC0", "MAC1", "MAC2",
					"MAC3", "IRGB", "ORGB", "LZCS", "LZCR"]

		
		if (op.specval == self.DATA_REG):
			return data_regs[op.reg].lower()
		elif (op.specval == self.CTRL_REG):
			return ctrl_regs[op.reg].lower()
		else:
			return "UNK"

	def decode_sf_lm(self, dword):

		sf = (dword >> 19) & 1
		lm = (dword >> 10) & 1
		return "sf={:d}, lm={:d}".format(sf, lm)

	def decode_mvmva(self, dword):

		sf = (dword >> 19) & 1
		mm = (dword >> 17) & 3
		mv = (dword >> 15) & 3
		tv = (dword >> 13) & 3
		lm = (dword >> 10) & 1
		return "sf={:d}, mm={:d}, mv={:d}, tv={:d}, lm={:d}".format(sf, mm, mv, tv, lm)

	def ev_out_operand(self, ctx, op):
		if (ctx.insn.itype >= ITYPE_START and ctx.insn.itype < ITYPE_START + len(self.itable) and op.n == 0):

			if (self.itable[ctx.insn.itype - ITYPE_START].name == "mvmva"):
				s=self.decode_mvmva(ida_bytes.get_wide_dword(ctx.insn.ea))
				ctx.out_line(s, 4)
				return 1
			else:
				s=self.decode_sf_lm(ida_bytes.get_wide_dword(ctx.insn.ea))
				ctx.out_line(s, 4)
				return 1

		elif (op.type == ida_ua.o_idpspec1 and op.reg < 32):

			# First we need to fix instructions (badly) disassembled by mips.dll
			if (ctx.insn.itype == self.CFC2_ITABLE_ID and op.n == 1):
				op.specval = self.CTRL_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype == self.CTC2_ITABLE_ID and op.n == 1):
				op.specval = self.CTRL_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype == self.MTC2_ITABLE_ID and op.n == 1):
				op.specval = self.DATA_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype == self.MFC2_ITABLE_ID and op.n == 1):
				op.specval = self.DATA_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype == self.LWC2_ITABLE_ID and op.n == 0):
				op.specval = self.DATA_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype == self.SWC2_ITABLE_ID and op.n == 0):
				op.specval = self.DATA_REG
				ctx.out_register(self.get_register(op, ctx))
			elif (ctx.insn.itype >= ITYPE_START and ctx.insn.itype < ITYPE_START + len(self.itable)):
				ctx.out_register(self.get_register(op, ctx))
			else:
				return 0

			return 1

		return 0

	def ev_out_mnem(self, ctx):
		if (ctx.insn.itype >= ITYPE_START and ctx.insn.itype < ITYPE_START + len(self.itable)):
			
			ctx.out_custom_mnem(self.itable[ctx.insn.itype - ITYPE_START].name, MNEM_WIDTH, "")
			return 1

		# We do this to fix width of other instructions
		ctx.out_mnem(MNEM_WIDTH)
		return 1

class gte_plugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = ""
	help = ""
	wanted_name = "PSX GTE COP2 instructions disassembler"
	wanted_hotkey = ""

	def __init__(self):
		self.gte = None

	def init(self):
		
		if (ida_ida.inf_get_procname() == 'mipsl'):
			self.gte = GTE_disassemble()
			self.gte.hook()
			print("PSX GTE COP2 instructions disassembler loaded.")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP

	def run(self, arg):
		pass

	def term(self):
		if (self.gte != None):
			self.gte.unhook()
			self.gte = None

def PLUGIN_ENTRY():
	return gte_plugin_t()
