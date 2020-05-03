from angr import SimProcedure

class VFG_HeapRegion:
    def __init__(self, base_addr, length):
        self._base_addr = base_addr
        self._length    = length


class MallocProcedure(SimProcedure):
    def run(self, size, vfg = None, vfg_heapmanager = None):
        #print ("VFG_HeapRegion -- malloc hooked !")

        alloc_ctx = vfg_heapmanager.get_heap_alloc_ctx()
        
        size_vsa = size._model_vsa
        size_vsa_min = size_vsa.min

        ## FIXME: is it OK ?
        heap_size = size_vsa_min
        heap_ptr  = vfg_heapmanager.alloc_heap_region(heap_size)
        #vfg_heapmanager._alloc_regions[alloc_ctx] = VFG_HeapRegion(heap_ptr, heap_size)

        self.state.memory.add_heap_address_mapping(heap_ptr, heap_size, alloc_ctx)

        print ("malloc: heap_ptr = " + hex(heap_ptr) + ", alloc-ctx = " + alloc_ctx)
 
        return heap_ptr


class FreeProcedure(SimProcedure):
    def run(self, ptr, vfg = None, vfg_heapmanager = None):
        ptr_vsa     = ptr._model_vsa
        ptr_vsa_min = ptr_vsa.min
        self.state.memory.remove_heap_address_mapping(ptr_vsa_min)

'''
class CallocProcedure(SimProcedure):
    def run(self, vfg = None, vfg_heapmanager = None):
        pass
'''

class VFG_HeapManager:
    def __init__(self, project, vfg, min_addr, max_addr):
        self._project  = project
        self._vfg      = vfg
        self._min_addr = min_addr
        self._max_addr = max_addr
        #self._alloc_regions = {}  ## <alloc_id, region>

        self._curr_heap_pos = min_addr

    def remove_heap_region_by_id(heap_id):
        if not (heap_id in self._alloc_regions):
            print ("invalid heap_id " + heap_id + " encountered in VFG_HeapRegion !")
            exit (0)

        del self._alloc_regions[heap_id]

    def alloc_heap_region(self, size):
        heap_ptr = self._curr_heap_pos
        self._curr_heap_pos = self._curr_heap_pos + size 
        return heap_ptr

    def get_alloc_region_by_va(self, addr):
        pass

    def get_heap_alloc_ctx(self):
        job = self._vfg.get_current_job()
        if (job is None):
            return None
        return "heap_" + str(job._block_id)


    def build_heapHooks(self):
        self._project.hook_symbol('malloc', MallocProcedure(vfg = self._vfg, vfg_heapmanager = self))
        self._project.hook_symbol('free', FreeProcedure(vfg = self._vfg, vfg_heapmanager = self))
        #pass





