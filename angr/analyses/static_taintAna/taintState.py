#
from sortedcontainers import SortedDict
from enum import Enum

class TAINT_SRC_TYPE(Enum):
    STDIN   = 0
    FILE    = 1
    NETWORK = 2

    @classmethod
    def toString(self, tsrc_type):
        if tsrc_type is TAINT_SRC_TYPE.STDIN:
            return "STDIN"
        elif tsrc_type is TAINT_SRC_TYPE.FILE:
            return "FILE"
        elif tsrc_type is TAINT_SRC_TYPE.NETWORK:
            return "NET"
        else:
            raise Exception("invalid TAINT_SRC_TYPE specified !")


class TaintMetaData:

    def __init__(self):
        pass

    def set_taint_info(self, taintSrc, taintSite):
        self.taintSrc  = taintSrc
        self.taintSite = taintSite

    def copy(self):
        td = TaintMetaData()
        td.taintSrc  = self.taintSrc
        td.taintSite = self.taintSite
        return td
    
    def dump(self):
        outStr = "taint: " + \
                 "src  = " + TAINT_SRC_TYPE.toString(self.taintSrc) + ", " + \
                 "site = " + str(self.taintSite)
        print (outStr)
                 

class TaintSet:

    def __init__(self):
        self.storage = set()

    def update_tval(self, taint_metadata):
        self.storage.clear()

        ## empty set meaning 'untainted'
        if taint_metadata != None:
            self.storage.add(taint_metadata)
        
    def update_tset(self, taint_set):
        self.storage.clear()
        if taint_set != None:
            self.storage = taint_set.copy()
        
    def merge(self, taint_metadata):
        ## merging 'untainted' is meaningless
        if (taint_metadata == None):
            return

        for item in self.storage:
            if (item.taintSrc == taint_metadata.taintSrc) and (item.taintSite == taint_metadata.taintSite):
                return
        self.storage.add(taint_metadata)

    def merge_set(self, taint_set):
        for item in taint_set.storage:
            self.merge(item)

    def add(self, item):
        self.storage.add(item)

    def copy(self):
        new_tset = TaintSet()
        for item in self.storage:
            new_tset.add(item.copy())
        return new_tset

    def dump(self):
        for item in self.storage:
            item.dump()


class TaintRegion:

    def __init__(self):
        self.storage = SortedDict()

    def _write_byte_taint(self, addr, taintset, merge = False):
        to_update = dict()
        if merge:
            ## 现在、原来数据皆非空
            if not(taintset is None) and not(self.storage.get(addr) is None):
                old_taintset = self.storage[addr]
                taintset = taintset.merge_set(old_taintset)
            else:
                return
        else:
            if taintset is None:
                if self.storage.get(addr):
                    del self.storage[addr]
                    return

        to_update[addr] = taintset
        self.storage.update(to_update)

    def _read_byte_taint(self, addr):
            return self.storage.get(addr)

    '''
    ## write TaintSet to single byte
    def write_taint(self, addr, size, taintdata):
        i = 0
        while i < size:
            self._write_byte_taint( addr + i,
                                    taintdata
                                  )
            i = i + 1
    '''

    def write_taint(self, addr, size, taintdata_map, merge = False):
        i = 0
        if (taintdata_map is None) and (not merge):
            while i < size:
                self._write_byte_taint( addr + i,
                                        None,
                                        merge
                                      )
                i = i + 1
            return

        while i < size:
            self._write_byte_taint( addr + i, 
                                    taintdata_map[i],
                                    merge
                                  )
            i = i + 1

    '''
    def read_taint(self, addr, size):
        tset = TaintSet()
        i = 0
        while i < size:
            tmp_tset = self._read_byte_taint(addr + i)
            tset.merge_set(tmp_tset)
            i = i + 1
    '''

    def read_taint(self, addr, size):
        result = SortedDict()
        i = 0
        while i < size:
            result[i] = self._read_byte_taint(addr + i)
            i = i + 1
        return result

    def copy(self, new_region):
        for key, obj in self.storage.items():
            if obj is None:
                continue
            new_region.storage[key] = obj.copy()
            '''
            if (key == 0x804c040):
                print ("we copied 0x804c040's taint = ")
                print(new_region.storage[key])
            '''
 
        return new_region

    def dump(self):
        for addr, tset in self.storage.items():
            print ("vaddr = " + hex(addr) + ", taint-set = ")
            print ("---------------------------------------")
            tset.dump()
            print ("---------------------------------------")


class TaintRegion_stack(TaintRegion):
    def __init__(self, stack_base, stack_top):
        super(TaintRegion_stack, self).__init__()
        self.stack_base = stack_base
        self.stack_top  = stack_top

    def copy(self):
        ts = TaintRegion_stack(self.stack_base, self.stack_top)
        super(TaintRegion_stack, self).copy(ts)
        return ts


class TaintRegion_mem(TaintRegion):
    def __init__(self):
        super(TaintRegion_mem, self).__init__()

    '''
    def copy(self):
        super(TaintRegion_mem, self).copy(ts)
        print ("copying --- ")
        print (self.storage.keys())

        ts = TaintRegion_mem()
        for key, obj in self.storage.items():
           ts.storage[key] = obj.copy()
           if (key == 0x804c040):
                print ("we copied 0x804c040's taint = " + new_region.storage[key])
 
        return ts
    '''
    def copy(self):
        ts = TaintRegion_mem()
        super(TaintRegion_mem, self).copy(ts)
        for key, obj in self.storage.items():
            if obj is None:
                continue
            ts.storage[key] = obj.copy()
            '''
            if (key == 0x804c040):
                print ("we copied 0x804c040's taint = ")
                print(ts.storage[key])
            '''
 
        return ts

   

class TaintRegion_tmp(TaintRegion):
    pass


class TaintRegion_reg(TaintRegion):
    def __init__(self):
        super(TaintRegion_reg, self).__init__()

    def copy(self):
        ts = TaintRegion_reg()
        super(TaintRegion_reg, self).copy(ts)
        return ts


class TaintRegion_heap(TaintRegion):
    pass


class TaintState:

    STACK_REGION = 0
    MEM_REGION   = 1
    REG_REGION   = 2
    TMP_REGION   = 3
    HEAP_REGION  = 4

    def __init__(self, stack_base):
        self.stack_base       = stack_base
        self.stack_max_top    = self.stack_base - (0x1000 * 10)

        self.stack_taintState = TaintRegion_stack( self.stack_base,
                                                   self.stack_max_top
                                                 )
        self.mem_taintState   = TaintRegion_mem()
        self.reg_taintState   = TaintRegion_reg()
        
        ## TMPs' taint states should be constructed at engine.process()'s startup, through 'build_tmp_taint_context'
        #self.tmp_taintState   = TaintRegion_tmp()

        ## <alloc_codeloc, heapRegion>
        ## self.heap_taintState  = dict() 

    def build_tmp_taint_context(self):
        self.tmp_taintState = TaintRegion_tmp()
        
        ## < id(expr), SortedDict(offset, TaintSet) >
        self.expr_taintMap  = dict()
        
    def copy(self):
        taint_state = TaintState(self.stack_base) 
        taint_state.stack_taintState = self.stack_taintState.copy()
        
        taint_state.mem_taintState   = self.mem_taintState.copy()

        #taint_state.mem_taintState.copy(self.mem_taintState)
        taint_state.reg_taintState   = self.reg_taintState.copy()
        
        taint_state.tmp_taintState = TaintRegion_tmp()
        taint_state.expr_taintMap = dict()
        return taint_state

    ## read utils
    def get_register_taint(self, regidx, size):
        return self.reg_taintState.read_taint(regidx, size)

    def get_tmp_taint(self, tmpidx, size):
        return self.tmp_taintState.read_taint(tmpidx, size)

    # returns SortedDict(addr, TaintSet)
    def get_memory_taint(self, addr, size):
        if ( (addr >= self.stack_max_top) and (addr <= self.stack_base) ):
            return self.stack_taintState.read_taint(addr, size)
        else:
            #return self.mem_taintState.read_taint(addr, size)
            ts = self.mem_taintState.read_taint(addr, size)

            '''
            if (addr == 0x804c040):
                if ts is None:
                    print ("monitor get: taint is None !")
                else:
                    i = 0
                    while i < 4:
                        if ts[i] is None:
                            print ("[" + str(i) + "] is None ")
                        else:
                            print ("[" + str(i) + "] is tainted !")
                        i = i + 1
            '''
            return ts

    def get_expr_taint(self, expr_id, size):
        if (self.expr_taintMap.get(expr_id) is None):
            return None
        return self.expr_taintMap[expr_id]


    ## write utils
    def update_register_taint(self, regidx, size, taintdata_map, merge = False):
        self.reg_taintState.write_taint( regidx, 
                                         size, 
                                         taintdata_map, 
                                         merge = False
                                       )

    def update_tmp_taint(self, tmpidx, size, taintdata_map, merge = False):
        self.tmp_taintState.write_taint( tmpidx, 
                                         size, 
                                         taintdata_map, 
                                         merge = False
                                       )

    def update_memory_taint(self, addr, size, taintdata_map, merge = False):
        if (addr >= self.stack_max_top) and (addr <= self.stack_base):
            self.stack_taintState.write_taint( addr, 
                                               size, 
                                               taintdata_map, 
                                               merge = False
                                             )
        else:
            self.mem_taintState.write_taint( addr, 
                                             size, 
                                             taintdata_map, 
                                             merge = False
                                           )

    '''
    taint_offset_dict: { <0, TaintSet>, <1, TaintSet>, ... }
    '''
    def update_expr_taint(self, expr_id, size, taint_offset_dict, merge = False):
        if not merge:
            self.expr_taintMap[expr_id] = taint_offset_dict
            return

        if taint_offset_dict is None:
            return

        old_taint_offset_dict = self.expr_taintMap.get(expr_id)
        if old_taint_offset_dict is None:
            self.expr_taintMap[expr_id] = taint_offset_dict
            return

        i = 0
        while i < size:
            if taint_offset_dict.get(i) is None:
                taint_offset_dict[i] = old_taint_offset_dict[i]
            elif not(old_taint_offset_dict.get(i) is None):
                taint_offset_dict[i].merge_set(old_taint_offset_dict[i])
            i = i + 1

        self.expr_taintMap[expr_id] = taint_offset_dict
