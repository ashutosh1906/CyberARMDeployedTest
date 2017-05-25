################################################################## File Names #############################################

############################################################## Global Variables #############################################
OTHER_ASSET = 'other'
DESTROY_C = 4
DESTROY_I = 2
DESTROY_A = 1
THREAT_ACTION_UNKNOWN_TAG = 'unknown'
HACKING_COST = DESTROY_C | DESTROY_I | DESTROY_A
MALWARE_COST = DESTROY_C | DESTROY_I | DESTROY_A
SOCIAL_COST = DESTROY_C | DESTROY_I | DESTROY_A
ENVIRONMENTAL_COST = DESTROY_C | DESTROY_I | DESTROY_A
ERROR_COST = DESTROY_C | DESTROY_I | DESTROY_A
MISUSE_COST = DESTROY_C | DESTROY_I | DESTROY_A
PHYSICAL_COST = DESTROY_C | DESTROY_I | DESTROY_A
THREAT_MAP_COST = {}
THREAT_PRIORITIZATION_THRESHOLD = 0.05

######################################### Kill chain phase dimension ##################################################
RECON_KEY = 'recon'
WEAPONIZE_KEY = 'weaponize'
DELIVER_KEY = 'deliver'
EXPLOIT_KEY = 'exploit'
CONTROL_KEY = 'control'
EXECUTE_KEY = 'execute'
MAINTAIN_KEY = 'maintain'
KILL_CHAIN_PHASE_LIST = []
KILL_CHAIN_PHASE_TO_ID = {}
ID_TO_KILL_CHAIN_PHASE = {}

################################################## Enforcement Level Dimension ########################################
ENFORCEMENT_LEVEL_LIST = ['network','device','application','data','people']
ENFORCEMENT_LEVEL_TO_ID = {}
ID_TO_ENFORCEMENT_LEVEL = {}

################################################## Security Function Dimension ########################################
SECURITY_FUNCTION_LIST = ['identify','protect','detect','respond','recover']
SECURITY_FUNCTION_TO_ID = {}
ID_TO_SECURITY_FUNCTION = {}

def init_conf():
    THREAT_MAP_COST['malware'] = MALWARE_COST
    THREAT_MAP_COST['hacking'] = HACKING_COST
    THREAT_MAP_COST['social'] = SOCIAL_COST
    THREAT_MAP_COST['environmental'] = ENVIRONMENTAL_COST
    THREAT_MAP_COST['error'] = ERROR_COST
    THREAT_MAP_COST['misuse'] = MISUSE_COST
    THREAT_MAP_COST['physical'] = PHYSICAL_COST

    ################################################# map to kill-chain-phase ################################################################
    KILL_CHAIN_PHASE_LIST.append(RECON_KEY)
    KILL_CHAIN_PHASE_LIST.append(WEAPONIZE_KEY)
    KILL_CHAIN_PHASE_LIST.append(DELIVER_KEY)
    KILL_CHAIN_PHASE_LIST.append(EXPLOIT_KEY)
    KILL_CHAIN_PHASE_LIST.append(CONTROL_KEY)
    KILL_CHAIN_PHASE_LIST.append(EXECUTE_KEY)
    KILL_CHAIN_PHASE_LIST.append(MAINTAIN_KEY)
    for i in range(len(KILL_CHAIN_PHASE_LIST)):
        KILL_CHAIN_PHASE_TO_ID[KILL_CHAIN_PHASE_LIST[i]] = i
        ID_TO_KILL_CHAIN_PHASE[i] = KILL_CHAIN_PHASE_LIST[i]

    ###################################################### Map to Enforcement Level ################################################################
    for i in range(len(ENFORCEMENT_LEVEL_LIST)):
        ENFORCEMENT_LEVEL_TO_ID[ENFORCEMENT_LEVEL_LIST[i]] = i
        ID_TO_ENFORCEMENT_LEVEL[i] = ENFORCEMENT_LEVEL_LIST[i]

    ############################################## MAP TO SECURITY FUNCTION ############################################################################
    for i in range(len(SECURITY_FUNCTION_LIST)):
        SECURITY_FUNCTION_TO_ID[SECURITY_FUNCTION_LIST[i]] = i
        ID_TO_SECURITY_FUNCTION[i] = SECURITY_FUNCTION_LIST[i]


