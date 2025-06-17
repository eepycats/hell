#include "bytes.hpp"
#include "nalt.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <ios>
#include <pro.h>
#include <idalib.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <iostream>
#include <linuxpe>
#include <segment.hpp>
#include <utility>
#include <vector>
#include <fstream>
#include <print>

coff::section_characteristics_t characteristics_for_section(qstring& str){
	coff::section_characteristics_t ret{};
	if (str == ".text"){
		ret.cnt_code = 1;
		ret.mem_execute = 1;
		ret.mem_read = 1;
		return ret;
	}

	if (str == ".rdata") {
		ret.cnt_init_data = 1;
		ret.mem_read = 1;
		return ret;
	}
	
	if (str == ".data" or str== ".tls") {
		ret.cnt_init_data = 1;
		ret.mem_read = 1;
		ret.mem_write = 1;
		return ret;
	}
	throw std::exception("unknown section in ch_for_sc");
}

int main(int argc,char* argv[]) {
	try {
		int ok = init_library();
		if (ok != 0) {
			throw std::exception("!ok");
		}
		ok = open_database("<redacted>", false);
		if (ok != 0) {
			throw std::exception("!ok x2");
		}

		uint32_t import_directory_start = 0xffffffff;
		uint32_t import_directory_end = 0;

		uint32_t tls_directory_start = 0;
		uint32_t tls_directory_end = 0;

		uint32_t load_configuration_directory_start = 0xffffffff;
		uint32_t load_configuration_directory_end = 0;
		
		uint32_t iat_start = 0;
		uint32_t iat_end = 0;
		
		uint32_t base = get_imagebase();
		uint32_t ep = 0;
		size_t name_count = get_nlist_size();
		for (size_t i = 0; i < name_count; ++i)
		{
			ea_t ea = get_nlist_ea(i);
			const char* name = get_nlist_name(i);
			if (name != nullptr && name[0] != '\0')
			{
				std::string str(name);
				if (str.starts_with("__IMPORT_DESCRIPTOR_")){
					import_directory_start = std::min(import_directory_start, static_cast<uint32_t>(ea));
					import_directory_end = std::max(import_directory_end, static_cast<uint32_t>(ea+20));
					continue;
				}
				if (str == "__tls_used"){
					tls_directory_start = ea;
					tls_directory_end = ea+24;
					continue;
				}
				if (str == "__load_config_used"){
					load_configuration_directory_start = ea;
					load_configuration_directory_end = ea+72;
					continue;
				}
				if (str == "_WinMainCRTStartup"){
					ep = ea;
					continue;
				}
			}
		}
		std::list<std::pair<win::section_header_t, std::vector<uint8_t>>> sections;
		auto section_by_name = [&](const char* _name) -> std::pair<win::section_header_t, std::vector<uint8_t>>&
		{
			auto it = std::find_if(sections.begin(), sections.end(),
					[&_name](std::pair<win::section_header_t, std::vector<uint8_t>>& member) {
						return member.first.name.equals(_name);
					});
			if (it == sections.end()) throw std::exception("balls");
			return *it;
		};
		// iat
		for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea))
		{
			qstring name;
			get_segm_name(&name, seg);
			ea_t start = seg->start_ea;
			ea_t end = seg->end_ea;
			//auto perm = seg->perm;
			auto size = end-start;
			std::println("{} {:x} {:x} {:x}", name.c_str(), start,end,size);

			if (name == ".rdata"){
				auto it = std::find_if(sections.begin(), sections.end(),
					[](std::pair<win::section_header_t, std::vector<uint8_t>>& member) {
						return member.first.name.equals(".rdata");
					});
				if (it == sections.end()){
					throw std::exception("abysmal dogshit");
				}
				auto& pair = *it;
				pair.first.virtual_size += size;
				pair.first.size_raw_data += size;
				std::vector<uint8_t> temp_vector(size);
				get_bytes(temp_vector.data(), size, start);
				pair.second.insert(pair.second.end(), temp_vector.begin(), temp_vector.end());
				continue;
			}

			if (name == ".idata"){
				iat_start = start;
				iat_end = end;
				name = ".rdata";	// abysmal dogshit
			}

			if (true){
				win::section_header_t hdr{};
				//memset(&hdr.name.short_name, 0, 8);
				memcpy(hdr.name.short_name, name.c_str(), std::min(static_cast<int>(name.size()),8));
				hdr.virtual_size = size;
				hdr.size_raw_data = size;
				hdr.virtual_address = start-base;
				hdr.characteristics = characteristics_for_section(name);
				// ptr_to_raw_data is filled later
				std::vector<uint8_t> vec;
				vec.resize(size);
				get_bytes(vec.data(), size, start);
				sections.push_back(std::make_pair(hdr,vec));
				continue;
			}			
		}
		std::map<std::string, uint32_t> iat_bases = {
			{"ADVAPI32.dll", 0x00855000},
			{"DDRAW.dll", 0x0085501C},
			{"DSOUND.dll", 0x00855028},
			{"GDI32.dll",0x00855034},
			{"KERNEL32.dll", 0x0085504C},
			{"SHELL32.dll", 0x008552A4},
			{"USER32.dll", 0x008552AC},
			{"WINMM.dll", 0x008553A0},
			{"WSOCK32.dll", 0x008553D0},
			{"binkw32.dll", 0x00855434},
			{"d3d9.dll", 0x00855480},
			{"mss32.dll",0x00855488}
		};

		auto& _rdata = section_by_name(".rdata");
		auto rva_to_rdata_off = [&](uint32_t rva) -> uint32_t {
			auto mem_mapped_addr = (_rdata.first.virtual_address + base);
			return rva-mem_mapped_addr;
		};
		//uint32_t iat_cur = 0x00855000-base;
		auto import_dir_off = rva_to_rdata_off(import_directory_start);
		auto imp_dir_ptr = reinterpret_cast<win::import_directory_t*>(_rdata.second.data() + import_dir_off);
		auto imp_dir_size = import_directory_end-import_directory_start;
		for (int i = 0; i < imp_dir_size/sizeof(win::import_directory_t); i++){
			auto dll_name_off = rva_to_rdata_off(base+imp_dir_ptr->rva_name);
			auto dll_name = reinterpret_cast<const char*>(_rdata.second.data()+dll_name_off);
			//std::cout << reinterpret_cast<const char*>(_rdata.second.data()+dll_name_off) << '\n';
			//std::println("{} {:x} {:x}",reinterpret_cast<const char*>(_rdata.second.data()+dll_name_off), imp_dir_ptr->rva_original_first_thunk, imp_dir_ptr->rva_first_thunk);
        	uint32_t thunk_fakerva = imp_dir_ptr->rva_original_first_thunk;
			uint32_t thunk_off = rva_to_rdata_off(base+thunk_fakerva);
			auto thunk_ptr = reinterpret_cast<win::image_thunk_data_x86_t*>(_rdata.second.data()+thunk_off);

			// target
			std::string s(dll_name);
			std::println("real iat base {:x}", iat_bases[s] - base);
			imp_dir_ptr->rva_first_thunk = iat_bases[dll_name] - base;
        	uint32_t target_thunk_fakerva = imp_dir_ptr->rva_first_thunk;
			uint32_t target_thunk_off = rva_to_rdata_off(base+target_thunk_fakerva);
			auto target_thunk_ptr = reinterpret_cast<win::image_thunk_data_x86_t*>(_rdata.second.data()+target_thunk_off);

			int j = 0;
			while (thunk_ptr->address) {
				if (thunk_ptr->is_ordinal) {
					std::println("{} : import by ordinal {}", dll_name, static_cast<int>(thunk_ptr->ordinal));
				} else {
					uint32_t fakerva_name = thunk_ptr->address;
					uint32_t name_off = rva_to_rdata_off(base+fakerva_name);
					auto stupid_struct = reinterpret_cast<win::image_named_import_t*>(_rdata.second.data()+name_off);
					auto name = reinterpret_cast<const char*>(&stupid_struct->name);
					std::println("{} : import by name {} : {}", dll_name, name, thunk_ptr->address);
				}
				std::println("{:x}", target_thunk_fakerva+base);
				(target_thunk_ptr + j)->address = thunk_ptr->address;
				std::println("{:x}",(target_thunk_ptr + j)->address);
				thunk_ptr++;
				j++;
			}
			imp_dir_ptr++;
		}


		// shrink data
		auto round_up_to_4096 = [](size_t value) {
			return (value + 0xFFF) & ~0xFFF;
		};

		auto shrink_pe_section = [&](std::pair<win::section_header_t, std::vector<uint8_t>>& section) {
			size_t size = section.second.size();

			for (size_t i = 0; i < size; i++) {
				if (section.second[i] == 0x00) {
					bool all_zero = std::all_of(section.second.begin() + i, section.second.end(),
												[](uint8_t b) { return b == 0x00; });

					if (all_zero) {
						size_t trimmed_size = round_up_to_4096(i);
						section.second.resize(trimmed_size);
						section.first.size_raw_data = section.second.size();
						return;
					}
				}
			}
		};

		shrink_pe_section(section_by_name(".data"));
		//return 1;
		win::image_t<false> image;
		image.dos_header.e_magic = win::DOS_HDR_MAGIC;
		image.dos_header.e_cblp = 0x0090;
		image.dos_header.e_cp = 0x0003;
		image.dos_header.e_crlc = 0x0000;
		image.dos_header.e_cparhdr = 0x0004;
		image.dos_header.e_minalloc = 0x0000;
		image.dos_header.e_maxalloc = 0xFFFF;
		image.dos_header.e_ss = 0x0000;
		image.dos_header.e_sp = 0x00B8;
		image.dos_header.e_csum = 0x0000;
		image.dos_header.e_ip = 0x0000;
		image.dos_header.e_cs = 0x0000;
		image.dos_header.e_lfarlc = 0x0040;
		image.dos_header.e_ovno = 0x0000;
		std::memset(image.dos_header.e_res,0,sizeof(image.dos_header.e_res));
		image.dos_header.e_oemid = 0x0000;
		image.dos_header.e_oeminfo = 0x0000;
		std::memset(image.dos_header.e_res2,0,sizeof(image.dos_header.e_res2));
		image.dos_header.e_lfanew = 0x68;

		win::nt_headers_t<false> _hdrs;
		auto hdrs = &_hdrs;
		hdrs->file_header.machine = coff::machine_id::i386;
		hdrs->file_header.num_sections = sections.size();
		hdrs->file_header.size_optional_header = sizeof(win::optional_header_x86_t);
		hdrs->file_header.characteristics.relocs_stripped = 1;
		hdrs->file_header.characteristics.executable = 1;
		hdrs->file_header.characteristics.machine_32 = 1;

		hdrs->signature = win::NT_HDR_MAGIC;

		auto& opt= hdrs->optional_header;
		opt.magic = 0x10b;
		opt.linker_version.major = 0;
		opt.linker_version.minor = 0;
		opt.size_code = section_by_name(".text").first.virtual_size;
		opt.size_init_data = section_by_name(".rdata").first.size_raw_data + section_by_name(".tls").first.size_raw_data + section_by_name(".data").first.size_raw_data;
		opt.size_uninit_data = 0;
		opt.entry_point = ep-base;
		opt.base_of_code = 0x1000;
		opt.base_of_data = section_by_name(".rdata").first.virtual_address;
		opt.image_base = base;
		opt.section_alignment = 0x1000;
		opt.file_alignment = 512;
		opt.os_version.major = 4;
		opt.os_version.minor = 0;
		opt.img_version.identifier = 0;
		opt.subsystem_version.major = 4;
		opt.subsystem_version.minor = 0;
		opt.win32_version_value = 0;
		//static_assert(sizeof(win::nt_headers_t<false>) != sizeof(win::file_header_t) + sizeof(uint32_t) + sizeof(win::optional_header_x86_t), "fuck");
		// 64 dos
		// 40 stub (padding)
		// 68 dos
		// 248 nt_all
		// 4 * 40 = 160
		// = 512 for headers
		opt.size_image = 512;
		uint32_t section_cnt = 512;
		for (auto& section : sections) {
			section.first.ptr_raw_data = section_cnt;
			section_cnt += section.first.size_raw_data;
			opt.size_image += section.first.virtual_size;
		}
		opt.size_headers = 512;
		opt.checksum = 0;
		opt.subsystem = win::subsystem_id::windows_gui;
		opt.characteristics.flags = 0;
		opt.size_stack_reserve = 0xa0000;
		opt.size_stack_commit = 0x1000;
		opt.size_heap_reserve = 0x100000;
		opt.size_heap_commit = 0x1000;
		opt.ldr_flags = 0;
		opt.num_data_directories = 0x10;
		
		std::memset(&opt.data_directories, 0, sizeof(opt.data_directories));

		opt.data_directories.import_directory.rva = import_directory_start-base;
		opt.data_directories.import_directory.size = import_directory_end-import_directory_start;

		opt.data_directories.tls_directory.rva = tls_directory_start-base;
		opt.data_directories.tls_directory.size = tls_directory_end-tls_directory_start;

		opt.data_directories.load_config_directory.rva = load_configuration_directory_start-base;
		opt.data_directories.load_config_directory.size = load_configuration_directory_end-load_configuration_directory_start;

		opt.data_directories.iat_directory.rva = iat_start-base;
		opt.data_directories.iat_directory.size = iat_end-iat_start;

		// the finale
		std::ofstream out("imgoingtokillmyselfifthisdoesntwork2.exe", std::ios_base::binary);
		
		//dos
		out.write(reinterpret_cast<char*>(&image.dos_header), sizeof(win::dos_header_t));
		std::array<char, 40> zeros = {};
		out.write(zeros.data(), zeros.size());

		//nt
		out.write(reinterpret_cast<char*>(hdrs), sizeof(win::nt_headers_x86_t));
		// section headers
		for (auto& section : sections) {
			out.write(reinterpret_cast<char*>(&section.first), sizeof(win::section_header_t));
		}


		for (auto& section : sections){
			std::string n(section.first.name.to_string());
			std::println("{} {:x} {:x} {:x}", n, section.first.virtual_address, section.first.size_raw_data, section.first.virtual_size);
		}

		// sections
		for (auto& section : sections) {
			out.write(reinterpret_cast<char*>(section.second.data()), section.second.size());
		}
		std::cout << "wrote\n";
		// pray
		out.close();
		close_database(false);
	} catch(std::exception& ex){
		std::cout << ex.what() << '\n';
		close_database(false);
	}

}