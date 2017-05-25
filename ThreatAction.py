class ThreatAction(object):
    def __init__(self,ids,name):
        self.primary_key = ids
        self.threat_action_name = name
        self.prob_given_threat_asset = {}
        self.applicable_security_controls = []
        self.security_control_index = {}
        self.number_security_controls = 0
        self.asset_applicable_security_controls = []
        self.asset_security_control_index = {}
        self.asset_number_security_controls = 0

    def clearAssetSpecificList(self):
        self.asset_number_security_controls = 0
        self.asset_security_control_index.clear()
        del self.asset_applicable_security_controls[:]

    def addAssetSpecificSecurityControl(self,security_control_entity_id):
        self.asset_security_control_index[security_control_entity_id] = self.asset_number_security_controls
        self.asset_applicable_security_controls.append(security_control_entity_id)
        self.asset_number_security_controls += 1

    def setProbThreatAction(self,prob_threat_action_threat,enterprise_asset_list_given):
        for asset in enterprise_asset_list_given:
            self.prob_given_threat_asset[asset] = {}
            for threat in prob_threat_action_threat[asset].keys():
                if self.threat_action_name in prob_threat_action_threat[asset][threat].keys():
                    self.prob_given_threat_asset[asset][threat] = prob_threat_action_threat[asset][threat][self.threat_action_name]

    def addSecurityControl(self,security_control_entity_id):
        if security_control_entity_id in self.applicable_security_controls:
            return
        self.applicable_security_controls.append(security_control_entity_id)
        self.security_control_index[security_control_entity_id] = self.number_security_controls
        self.number_security_controls += 1

    def printProperties(self,asset_name):
        print "\nID : %s Name : %s" % (self.primary_key,self.threat_action_name)
        print "Security Control %s" % (self.asset_applicable_security_controls)
        print "Security Control Index : %s" % (self.asset_security_control_index)
        print "Threat  --->"
        print "     For Asset Name %s " % (asset_name)
        for i in self.prob_given_threat_asset[asset_name].keys():
            print "                                      Threat Name : %s Prob %s" % (i,self.prob_given_threat_asset[asset_name][i])


