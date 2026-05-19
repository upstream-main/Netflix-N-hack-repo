-- ELF Dissector for PS3 by max
-- Reads raw_elf.bin lol.
local usb
for _, root in ipairs{"/dev_usb000","/dev_usb001","/dev_usb002","/dev_usb003"} do
    local f = io.open(root .. "/.t","w")
    if f then f:close(); os.remove(root .. "/.t"); usb = root; break end
end
if not usb then error("No USB") end

local elf_path = usb .. "/raw_elf.bin"
local out_dir = usb .. "/elf_sections"
pcall(fs.Mkdir, out_dir)

local report = io.open(usb .. "/elf_report.txt", "w")
report:setvbuf("no")
local function pr(...)
    for _, v in ipairs{...} do report:write(tostring(v)) end
    report:write("\n")
    report:flush()
end

local big = true
local function set_endian(byte) big = (byte == 2) end
local function r8(f) return f:read(1):byte() end
local function r16(f)
    local a,b = f:read(2):byte(1,2)
    return big and (a*256+b) or (b*256+a)
end
local function r32(f)
    local a,b,c,d = f:read(4):byte(1,4)
    return big and (a*16777216+b*65536+c*256+d) or (d*16777216+c*65536+b*256+a)
end
local function r64(f)
    local hi = r32(f)
    local lo = r32(f)
    return big and (hi * 4294967296 + lo) or (lo * 4294967296 + hi)
end

pr("=== ELF Dissection Report ===")
pr("File: " .. elf_path)

local f, err = io.open(elf_path, "rb")
if not f then f, err = io.open(elf_path, "r") end
if not f then pr("ERROR: " .. tostring(err)); report:close(); return end

-- 1. Check magic
local magic = f:read(4)
if magic ~= "\127ELF" then
    pr("Not an ELF file!")
    f:close(); report:close(); return
end
pr("ELF magic: OK")

-- 2. ELF identification
local ei_class = r8(f)
local ei_data  = r8(f)
set_endian(ei_data)
pr("Class: " .. (ei_class==1 and "32-bit" or "64-bit"))
pr("Endianness: " .. (ei_data==2 and "big" or "little"))
f:read(10)

-- 3. ELF header
local e_type    = r16(f)
local e_machine = r16(f)
local e_version = r32(f)
local e_entry   = (ei_class==2) and r64(f) or r32(f)
local e_phoff   = (ei_class==2) and r64(f) or r32(f)
local e_shoff   = (ei_class==2) and r64(f) or r32(f)
local e_flags   = r32(f)
local e_ehsize  = r16(f)
local e_phentsize = r16(f)
local e_phnum   = r16(f)
local e_shentsize = r16(f)
local e_shnum   = r16(f)
local e_shstrndx = r16(f)

pr(string.format("Type: %d (2=EXEC, 3=DYN)", e_type))
pr(string.format("Machine: 0x%X", e_machine))
pr(string.format("Entry point: 0x%X", e_entry))
pr(string.format("Program header offset: 0x%X, count: %d", e_phoff, e_phnum))
pr(string.format("Section header offset: 0x%X, count: %d", e_shoff, e_shnum))

-- 4. Read program headers
local phdrs = {}
f:seek("set", e_phoff)
for i = 1, e_phnum do
    local p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    if ei_class == 2 then
        p_type   = r32(f)
        p_flags  = r32(f)
        p_offset = r64(f)
        p_vaddr  = r64(f)
        p_paddr  = r64(f)
        p_filesz = r64(f)
        p_memsz  = r64(f)
        p_align  = r64(f)
    else
        p_type   = r32(f)
        p_offset = r32(f)
        p_vaddr  = r32(f)
        p_paddr  = r32(f)
        p_filesz = r32(f)
        p_memsz  = r32(f)
        p_flags  = r32(f)
        p_align  = r32(f)
    end
    table.insert(phdrs, {type=p_type, offset=p_offset, vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz, flags=p_flags})
end

pr("\n--- Program Headers ---")
for i, ph in ipairs(phdrs) do
    local tname = "UNKNOWN"
    if ph.type == 1 then tname = "LOAD"
    elseif ph.type == 2 then tname = "DYNAMIC"
    elseif ph.type == 3 then tname = "INTERP"
    elseif ph.type == 4 then tname = "NOTE"
    elseif ph.type == 0x700000A4 then tname = "SCE_PPURELA"
    end
    pr(string.format("PH %2d: %-10s vaddr=0x%X offset=0x%X filesz=0x%X memsz=0x%X flags=0x%X",
        i, tname, ph.vaddr, ph.offset, ph.filesz, ph.memsz, ph.flags))
end

-- 5. Read section headers
pr("\n--- Section Headers ---")
f:seek("set", e_shoff)
local sections = {}
for i = 0, e_shnum-1 do
    local sh_name = r32(f)
    local sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
    if ei_class == 2 then
        sh_type   = r32(f)
        sh_flags  = r64(f)
        sh_addr   = r64(f)
        sh_offset = r64(f)
        sh_size   = r64(f)
        sh_link   = r32(f)
        sh_info   = r32(f)
        sh_addralign = r64(f)
        sh_entsize   = r64(f)
    else
        sh_type   = r32(f)
        sh_flags  = r32(f)
        sh_addr   = r32(f)
        sh_offset = r32(f)
        sh_size   = r32(f)
        sh_link   = r32(f)
        sh_info   = r32(f)
        sh_addralign = r32(f)
        sh_entsize   = r32(f)
    end
    table.insert(sections, {
        name_idx = sh_name,
        type = sh_type,
        flags = sh_flags,
        addr = sh_addr,
        offset = sh_offset,
        size = sh_size,
        link = sh_link,
        info = sh_info,
        entsize = sh_entsize
    })
end

-- Read section name string table
local shstrtab = sections[e_shstrndx+1]
local shstr = ""
if shstrtab and shstrtab.offset > 0 and shstrtab.size > 0 then
    f:seek("set", shstrtab.offset)
    shstr = f:read(shstrtab.size) or ""
end

local function secname(idx)
    if not shstr then return "?" end
    local start = idx + 1
    local finish = shstr:find("\0", start)
    return finish and shstr:sub(start, finish-1) or shstr:sub(start)
end

-- Log and dump sections
for i, sec in ipairs(sections) do
    local name = secname(sec.name_idx)
    local typestr = "UNKNOWN"
    if sec.type == 0 then typestr = "NULL"
    elseif sec.type == 1 then typestr = "PROGBITS"
    elseif sec.type == 2 then typestr = "SYMTAB"
    elseif sec.type == 3 then typestr = "STRTAB"
    elseif sec.type == 4 then typestr = "RELA"
    elseif sec.type == 5 then typestr = "HASH"
    elseif sec.type == 6 then typestr = "DYNAMIC"
    elseif sec.type == 7 then typestr = "NOTE"
    elseif sec.type == 8 then typestr = "NOBITS"
    elseif sec.type == 9 then typestr = "REL"
    elseif sec.type == 10 then typestr = "SHLIB"
    elseif sec.type == 11 then typestr = "DYNSYM"
    end
    pr(string.format("S %2d: %-16s type=%-8s addr=0x%X offset=0x%X size=0x%X",
        i-1, name, typestr, sec.addr, sec.offset, sec.size))
    
    -- Dump section to file if it has data and size > 0
    if sec.type ~= 0 and sec.size > 0 and sec.offset > 0 then
        local fname = name:gsub("[^%w%.%-]", "_")
        if fname == "" then fname = "section_" .. (i-1) end
        local out_path = out_dir .. "/" .. fname .. ".bin"
        f:seek("set", sec.offset)
        local data = f:read(sec.size)
        if data then
            local out = io.open(out_path, "wb") or io.open(out_path, "w")
            if out then
                out:write(data)
                out:close()
                pr("  -> saved " .. out_path)
            end
        end
    end
end

-- 6. Symbol tables
local function parse_symtab(sec_idx, symname)
    local sec = sections[sec_idx+1]
    if not sec or sec.size == 0 then return end
    local strtab_sec = sections[sec.link+1]
    if not strtab_sec then return end
    f:seek("set", sec.offset)
    local symdata = f:read(sec.size)
    f:seek("set", strtab_sec.offset)
    local strdata = f:read(strtab_sec.size)
    if not symdata or not strdata then return end

    pr("\n--- " .. symname .. " ---")
    local ent_size = sec.entsize
    if ent_size == 0 then ent_size = 16 end
    for pos = 1, #symdata, ent_size do
        local entry = symdata:sub(pos, pos+ent_size-1)
        if #entry < ent_size then break end
        -- Parse as 64-bit big-endian symbol (typical for PS3)
        local st_name = big and (entry:byte(1)*16777216+entry:byte(2)*65536+entry:byte(3)*256+entry:byte(4))
                            or (entry:byte(4)*16777216+entry:byte(3)*65536+entry:byte(2)*256+entry:byte(1))
        local st_info  = entry:byte(5)
        local st_other = entry:byte(6)
        local st_shndx = big and (entry:byte(7)*256+entry:byte(8)) or (entry:byte(8)*256+entry:byte(7))
        local st_value = 0
        for j = 9, 16 do st_value = st_value * 256 + entry:byte(j) end
        local st_size = 0
        if ent_size >= 24 then
            for j = 17, 24 do st_size = st_size * 256 + entry:byte(j) end
        end
        -- Get name
        local name = "?"
        if st_name > 0 and st_name < #strdata then
            local start = st_name + 1
            local finish = strdata:find("\0", start)
            name = strdata:sub(start, finish and finish-1)
        end
        local bind = bit32.band(bit32.rshift(st_info, 4), 0xF)
        local typ  = bit32.band(st_info, 0xF)
        if bind ~= 0 or typ ~= 0 then
            pr(string.format("%04d: %-32s val=0x%X size=%d shndx=%d bind=%d type=%d",
                (pos-1)/ent_size, name, st_value, st_size, st_shndx, bind, typ))
        end
    end
end

for i, sec in ipairs(sections) do
    if sec.type == 2 then parse_symtab(i-1, "SYMTAB")
    elseif sec.type == 11 then parse_symtab(i-1, "DYNSYM")
    end
end

-- 7. Entry point hex dump (256 bytes)
pr("\n--- Entry Point Code Dump (256 bytes) ---")
local text_offset = nil
for _, ph in ipairs(phdrs) do
    if ph.type == 1 and e_entry >= ph.vaddr and e_entry < ph.vaddr + ph.filesz then
        text_offset = ph.offset + (e_entry - ph.vaddr)
        break
    end
end
if text_offset then
    f:seek("set", text_offset)
    local code = f:read(256)
    if code then
        local hex, ascii = "", ""
        for i = 1, #code do
            local byte = code:byte(i)
            hex = hex .. string.format("%02X ", byte)
            ascii = ascii .. (byte>=32 and byte<127 and string.char(byte) or ".")
            if i % 16 == 0 then
                pr(string.format("0x%X: %-48s %s", e_entry + i - 16, hex, ascii))
                hex, ascii = "", ""
            end
        end
        if #hex > 0 then
            pr(string.format("0x%X: %-48s %s", e_entry + math.floor(#code/16)*16, hex, ascii))
        end
    end
else
    pr("Entry point not in any LOAD segment.")
end

f:close()
report:close()
pr("\nDone. Report: /elf_report.txt, Sections: /elf_sections/")
