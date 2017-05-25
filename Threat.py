class Threat(object):
    def __init__(self,ids,name):
        self.primary_key = ids
        self.threat_name = name
        self.asset_threat_action = []
        self.asset_threat_action_prob = []
        self.threat_action_id_to_place_map = {}
        self.number_threat_action = 0
        self.threat_impact_asset = []

    def clearApplicableThreatActions(self):
        self.threat_action_id_to_place_map.clear()
        del self.asset_threat_action[:]
        del self.asset_threat_action_prob[:]
        self.number_threat_action = 0

    def addThreatActionsAsset(self,threat_action_id):
        self.asset_threat_action.append(threat_action_id)
        self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
        self.number_threat_action += 1

    def addThreatImpact(self,risk_threat):
        for i in range(len(risk_threat)):
            if self.threat_name in risk_threat[i].keys():
                self.threat_impact_asset.append(risk_threat[i][self.threat_name])
            else:
                self.threat_impact_asset.append(0)

    def createAssetThreatAction(self,threat_action_id_list_for_specific_asset,asset_name,threat_action_list):
        self.clearApplicableThreatActions()
        for threat_action_id in threat_action_id_list_for_specific_asset:
            if self.threat_name in threat_action_list[threat_action_id].prob_given_threat_asset[asset_name].keys():
                self.asset_threat_action.append(threat_action_id)
                self.asset_threat_action_prob.append(threat_action_list[threat_action_id].prob_given_threat_asset[asset_name][self.threat_name])
                self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
                self.number_threat_action += 1

    def printProperties(self):
        print "\nID : %s Name : %s" % (self.primary_key,self.threat_name)
        print "Threat Impact %s" % (self.threat_impact_asset)
        print "Threat Action ------->"
        for i in range(len(self.asset_threat_action)):
            print "                          Threat Action ID : %s Prob : %s" % (self.asset_threat_action[i],self.asset_threat_action_prob[i])
        print "                          %s" % (self.asset_threat_action)
        print "                          %s" % (self.asset_threat_action_prob)