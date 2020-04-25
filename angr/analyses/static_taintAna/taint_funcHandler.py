from .atoms import Register
from .dataset import DataSet
from .taintState import * 

class STAFuncHandler:

    def __init__(self):
        pass
 
    def handle_local_function( #self, 
                               state, 
                               ip_addr, 
                               local_call_depth, 
                               maximum_local_call_depth, 
                               codeloc
                             ):
        #print ("handle_local_function: ip_addr = " + hex(ip_addr))

        #self.handle_function_num += 1

        ## let it modify the unique current state
        state = state.copy()
        analysis = state.analysis

        try:
            func = state.analysis.project.kb.functions.get_by_addr(ip_addr)
        except Exception:
            #self.ll.error('fail to find the function at 0x%x'%ip_addr)
            executed_rda = False
            return executed_rda, state
        #self.ll.warn('start to analyse the function: %s called at 0x%x'%(func.name, codeloc.ins_addr))
        try:
            sub_sta = state.analysis.project.analyses.StaticTaintAnalysis( func                     = func,
                                                                           block                    = None,
                                                                           func_graph               = None,
                                                                           max_iterations           = 3, 
                                                                           track_tmps               = False,
                                                                           observation_points       = None,
                                                                           init_state               = state,
                                                                           init_func                = False,
                                                                           cc                       = None,
                                                                           #function_handler         = STAFuncHandler,
                                                                           current_local_call_depth = local_call_depth,
                                                                           maximum_local_call_depth = maximum_local_call_depth,
                                                                           observe_all              = False
                                                                         )
        except Exception as e:
            #self.ll.error('analysing the function: %s called at 0x%x. %s'%(func.name, codeloc.ins_addr, e))
            print ('analysing the function throws an Exception : %s called at 0x%x. %s'%(func.name, codeloc.ins_addr, e))
            executed_rda = False
            return executed_rda, state

        if sub_sta.return_state is not None:
            print ('finish analysing function: %s called at 0x%x'%(func.name, codeloc.ins_addr))
            #state = sub_sta.return_state.copy()
            state = sub_sta.return_state.copy()
        else:
            print ('NONE return state of function: %s called at 0x%x'%(func.name, codeloc.ins_addr))
            executed_rda = False
            return executed_rda, state

        state.analysis = analysis
        executed_rda   = True

        return executed_rda, state
    
    
    def handle_unknown_call( #self, 
                             state, 
                             codeloc
                           ):
        state = state.copy()

        executed_rda = False
        return executed_rda, state
    
    def handle_indirect_call( #self, 
                              state, 
                              codeloc
                            ):
        state = state.copy()

        executed_rda = False
        return executed_rda, state


    ## Taint Functions
    def handle_read( #self, 
                     state, 
                     codeloc
                   ):
        
        if state.arch.name == 'X86' :
            defs_taint_fd  = state.memory_definitions.get_objects_by_offset(state.get_sp() + state.arch.bytes)
            defs_taint_buf = state.memory_definitions.get_objects_by_offset(state.get_sp() + state.arch.bytes * 2)
            defs_taint_sz  = state.memory_definitions.get_objects_by_offset(state.get_sp() + state.arch.bytes * 3)
            
            taint_fd = next(iter(defs_taint_fd)).data.get_first_element()
            if (taint_fd == 0):
                taint_src = TAINT_SRC_TYPE.STDIN 
            else:
                taint_src = TAINT_SRC_TYPE.FILE
            
            ## TODO: symbolic size ??
            size      = next(iter(defs_taint_sz)).data.get_first_element()
            taint_buf = next(iter(defs_taint_buf)).data.get_first_element()
            
            taint_dict = dict()

            outstr = "read(): " + \
                     "taint-src = " + TAINT_SRC_TYPE.toString(taint_src) + ", " + \
                     "buf  = " + hex(taint_buf) + " " + \
                     "size = " + str(size)
            print (outstr)
            
            i = 0
            while i < size:
                tset  = TaintSet()
                tmeta = TaintMetaData()
                tmeta.set_taint_info(taint_src, codeloc)

                tset.update_tval(tmeta)
                taint_dict[i] = tset 
                i = i + 1
            
            '''
            ## fake definition 
            # ------------------------------------------------------------------
            state.analysis.kill_and_add_definition( MemoryLocation(taint_buf, size), 
                                                    codeloc, 
                                                    DataSet(0xdeadbeef, size * 8)
                                                  )
            # ------------------------------------------------------------------
            '''
            state.taint_state.update_memory_taint( taint_buf,
                                                   size,
                                                   taint_dict,
                                                   merge = False
                                                 )
            
            i = 0
            while i < 4:
                outStr = "taint[" + str(i) + "] = "
                if taint_dict[i] is None:
                    outStr = outStr + "None"
                else:
                    outStr = outStr + "taint"
                print (outStr)

                i = i + 1
                
            executed_rda = False
            return executed_rda, state
