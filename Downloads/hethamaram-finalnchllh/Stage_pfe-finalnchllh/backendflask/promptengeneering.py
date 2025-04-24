import logging

shared_alert_prompt_fr = """
Vous êtes un assistant chargé de générer des messages d’alerte sur la consommation énergétique à partir de données structurées. En vous basant sur les champs suivants, générez une alerte professionnelle et concise pour un client :

Champs d'entrée :
- Nom de l'appareil : {device}
- Valeur mesurée : {Value} {unit}
- Seuil : {threshold} {unit}
- Pourcentage de dépassement : {weekly_variation_percent}%


Respectez exactement la structure suivante :
**Observation initiale** : "Nous avons constaté que la consommation hebdomadaire de {Value} {unit}, contre un seuil de {threshold} {unit}."

**Note contextuelle** : "Ce dépassement de {weekly_variation_percent}%, [modeste/important/considérable], pourrait [ne pas indiquer un problème majeur / suggérer un besoin d’ajustements], mais souligne des pistes d’amélioration de l’efficacité énergétique."

**Actions recommandées**:
"""

shared_alert_prompt_en = """
You are an assistant that generates energy consumption alert messages using structured input data. Based on the following fields, generate a professional and concise alert for a client:

Input fields:
- Device label: {device}
- Measured value: {Value} {unit}
- Threshold: {threshold} {unit}
- Overrun percentage: {weekly_variation_percent}%

Follow this structure exactly:
**Opening Observation**: "We've observed that the weekly consumption for {device} exceeded the threshold, registering {Value} {unit} compared to the threshold of {threshold} {unit}."
**Contextual Note**: "This represents a [modest/notable/significant] overrun of {weekly_variation_percent}%, which may [not necessarily indicate a significant issue/suggest a need for adjustments] but highlights potential efficiency improvements."
**Recommended Actions**:
"""

thdv_prompt_en = """ 
Generate a structured alert message for elevated Total Harmonic Distortion of Voltage (THDV) using the provided structured fields. Follow exactly this format:  

**Issue**:  
- The measured THDV value for {device} is {Value}{unit}, which exceeds the threshold of {threshold}{unit} (e.g., IEEE Standard 519).  
- Include 1-2 possible root causes (e.g., non-linear loads, aging equipment, voltage imbalances).  

**Machine Context**:  
- The affected machine/area is "{device}".  
- Compare the current THDV of {Value}{unit} to historical norms .
- Highlight operational risks if unresolved (e.g., equipment overheating, efficiency losses).  

**Immediate Actions**:  
1. **Priority Action**: Direct the user to a dashboard or tool for real-time data.  
2. **Equipment Check**: Specific inspection step (e.g., "Test capacitor banks" or "Verify grounding").  
3. **Load Analysis**: Identify contributing loads/systems (e.g., "Audit VFDs or rectifiers").  

**Next Steps**:  
- 2 actionable mid/long-term fixes (e.g., "Harmonic filter installation", "Preventive maintenance schedule").  
- Reference expert intervention if needed (e.g., "Consult power quality specialist").  
"""
thdv_prompt_fr = """  
Générez une alerte structurée pour une distorsion harmonique totale de tension (THDT) élevée en utilisant les champs structurés suivants. Suivez ce format :  

**Problème** :  
- La valeur THDV mesurée pour {device} est de {Value}{unit}, dépassant le seuil de {threshold}{unit} (ex. : norme IEEE 519).  
- Indiquez 1 à 2 causes potentielles (ex. : charges non linéaires, équipements vieillissants, déséquilibres de tension).  

**Contexte Machine** :  
- La machine ou zone concernée est "{device}".  
- Comparez la THDT actuelle de {Value}{unit} aux normes historiques (ex. : "Fonctionne normalement en dessous de X%").  
- Soulignez les risques opérationnels si non résolu (ex. : surchauffe, pertes d'efficacité).  

**Actions Immédiates** :  
1. **Action Prioritaire** : Diriger l'utilisateur vers un tableau de bord pour des données en temps réel.  
2. **Vérification Équipement** : Étape d'inspection spécifique (ex. : "Tester les bancs de condensateurs" ou "Vérifier la mise à la terre").  
3. **Analyse des Charges** : Identifier les charges ou systèmes responsables (ex. : "Auditer les variateurs de fréquence ou redresseurs").  

**Étapes Suivantes**:  
- 2 solutions actionnables à moyen/long terme (ex. : "Installer des filtres anti-harmoniques", "Planifier un calendrier de maintenance préventive").  
- Mentionner une intervention experte si nécessaire (ex. : "Consulter un spécialiste en qualité de l'énergie").  
"""

subscribed_power_prompt_en = """
You are an assistant generating energy alerts for subscribed power threshold exceedances using structured input data. Based on the following fields, generate a professional and concise alert for the client.

Input fields:
- Device label: {device}
- Measured value: {Value} {unit}
- Subscribed threshold: {threshold} {unit}
- Overrun percentage: {overrun_pct}%

Follow this structure:

1. **Observation**: "The subscribed power limit for {device} has been exceeded. The measured power was {Value} {unit}, compared to the subscribed threshold of {threshold} {unit}."

2. **Impact Assessment**: "This indicates an overrun of {overrun_pct}%, which may result in additional demand charges or contractual penalties depending on the utility agreement."
3. **Immediate Actions**:
4. **Recommended Actions**: 
"""
subscribed_power_prompt_fr = """
Vous êtes un assistant générant des alertes de dépassement de seuil de puissance souscrite à partir de données structurées. En vous basant sur les champs suivants, rédigez une alerte professionnelle et concise pour le client.

Champs d'entrée :
- Nom de l'appareil : {device}
- Valeur mesurée : {Value} {unit}
- Seuil souscrit : {threshold} {unit}
- Pourcentage de dépassement : {overrun_pct}%

Structure à suivre :

1. **Observation** : "Le seuil de puissance souscrite pour {device} a été dépassé. La puissance mesurée est de {Value} {unit}, contre un seuil souscrit de {threshold} {unit}."

2. **Évaluation de l'impact** : "Cela représente un dépassement de {overrun_pct}%, susceptible d'entraîner des frais supplémentaires ou des pénalités contractuelles selon les conditions du fournisseur."
3. **Actions immédiates**:
4. **Actions recommandées**:
"""

day_alert = """
Generate a formal alert message (no greetings/sign-offs) for abnormal daily energy consumption variations using the provided data. Follow this structure:
1. Alert Paragraph:
- Begin with: "We have detected an unusual variation in daily electricity consumption at {device}."
- State:
  - Today’s consumption: {today_consumption} {unit}
  - Previous day’s consumption: {yesterday_consumption} {unit}
  - Threshold for deviation: {threshold} {unit}
- The variation percentage is {variation_percent}%.
- Add context (e.g., "This difference, noted between yesterday and today, could be due to equipment usage patterns or operational schedule changes.")

2. Immediate Actions:

3. Recommended Actions:
"""
day_alert_fr = """
Générez une alerte formelle (sans salutations ni formules de politesse) pour des variations anormales de la consommation quotidienne d'électricité en utilisant les données suivantes :
- Commencez par : "Nous avons détecté une variation inhabituelle de la consommation quotidienne d'électricité sur {device_label}."
- Indiquez :
  - Consommation aujourd'hui : {today_consumption} {unit}
  - Consommation la veille : {yesterday_consumption} {unit}
  - Seuil de déviation : {threshold} {unit}
- Le pourcentage de variation est de {variation_percent}%.
- Ajoutez un contexte (ex. : "Cet écart, observé entre hier et aujourd'hui, pourrait être dû à des changements dans l'utilisation des équipements ou dans les plannings opérationnels.")

2. Actions Immédiates  :

3. Actions Recommandées  :
"""
cosphi_prompt = """
Generate a formal, technical alert message (no greetings/bold text) for abnormal Power Factor (Cos φ) values using the provided data. Follow exactly this structure:
Alert Statement:
   - Open with: "The Power Factor (Cos φ) for {device} has dropped to {Value}, significantly below the fixed threshold of {threshold}."
   - Highlight operational/financial consequences (e.g., "This indicates inefficiencies in reactive power management and may lead to penalties").
Context:
   - Explain the significance of the Power Factor (e.g., "An optimal Cos φ close to 1 minimizes reactive energy losses").
   - Link the deviation to root causes (e.g., inductive loads, capacitor bank failures).
   - Mention monitoring window: "This deviation was observed at {detectedAt}."
Immediate Actions:
   - Suggest 2–3 urgent steps (e.g., "Check capacitor banks", "Inspect inductive machines").
Recommended Next Steps:
   - Suggest 2–3 long-term actions (e.g., "Install automatic power factor correction system", "Plan a technical audit")."""
cosphi_prompt_fr = """
Générez une alerte technique formelle (sans salutations ni texte en gras) pour des valeurs anormales du Facteur de Puissance (Cos φ) en utilisant les données fournies. Structurez le message comme suit :
Déclaration d'Alerte :
   - Débutez par : "Le Facteur de Puissance (Cos φ) sur {device} est descendu à {Value}, se situant nettement en dessous du seuil fixe de {threshold}."
   - Mentionnez les conséquences opérationnelles/financières (ex. : "Cela indique des inefficacités dans la gestion de l'énergie réactive et peut entraîner des pénalités").
Contexte :
   - Expliquez l'importance du Cos φ (ex. : "Un Cos φ optimal proche de 1 minimise les pertes d'énergie réactive").
   - Liez la déviation à des causes possibles (ex. : charges inductives, défaillance des bancs de condensateurs).
   - Mentionnez la période de surveillance : "Cette déviation a été observée à {detectedAt}."
Actions Immédiates :
   - Proposez 2–3 étapes urgentes (ex. : "Vérifiez les bancs de condensateurs", "Inspectez les équipements inductifs").
Étapes Suivantes Recommandées :
   - Proposez 2–3 mesures à plus long terme (ex. : "Installer un système automatique de correction du facteur de puissance", "Prévoir un audit technique").
"""

inactive_prompt = """
Generate a formal alert message (no greetings/bold text) for device inactivity using the provided JSON data. Follow this structure:

1. Alert Statement:
   - Open with: "Device {device} has been inactive for {hold_on} minutes detected at {detectedAt}."
   - Specify the alert type (e.g., "inactivity") and note potential causes (e.g., power loss, connectivity issues, manual shutdown).

2. Context:
   - Explain common reasons for inactivity (e.g., "Sudden disconnections may stem from planned maintenance, hardware faults, or network instability").

3. Immediate Actions:
   - 2-3 urgent steps to diagnose the issue (e.g., "Verify power supply", "Test network connectivity").
   - Use imperative verbs (e.g., "Check", "Reboot", "Confirm").

4. Recommended Actions if Inactivity Persists:
   - 2-3 escalations or technical interventions (e.g., "Contact support", "Schedule hardware inspection").
"""
inactive_prompt_fr = """
Générez un message d'alerte formel (sans salutations ni texte en gras) concernant l’inactivité d’un dispositif à partir des données JSON fournies. Suivez cette structure :

1. Déclaration d'Alerte :
   - Commencez par : "Le dispositif {device} est inactif depuis {hold_on} minutes détecté le {detectedAt}."
   - Précisez le type d'alerte (ex. : "inactivité") et mentionnez les causes possibles (ex. : coupure de courant, problèmes de connectivité, arrêt manuel).

2. Contexte :
   - Expliquez les causes fréquentes d’inactivité (ex. : "Les déconnexions soudaines peuvent résulter d’une maintenance planifiée, de défaillances matérielles ou d’une instabilité réseau").

3. Actions Immédiates :
   - Donnez 2 à 3 étapes urgentes pour diagnostiquer le problème (ex. : "Vérifiez l'alimentation", "Testez la connectivité réseau").
   - Utilisez des verbes impératifs (ex. : "Inspectez", "Redémarrez", "Confirmez").

4. Actions Recommandées si l’Inactivité Persiste :
   - Proposez 2 à 3 mesures d'escalade ou interventions techniques (ex. : "Contacter le support", "Planifier une inspection matérielle").
"""

weekly_math = """ 
You are an assistant that generates energy consumption alert messages using structured input data. Based on the following fields, generate a professional and concise alert for a client:
Using this data :
- Device label: {device}
- Measured value: {Value} {unit}
- Threshold: {threshold} {unit}
- Overrun percentage calculation: use exactly this format for the calculations :
<calculations>
  Step 1: {Value} - {threshold} = {difference} {unit}
  Step 2: ({difference}/{threshold}) × 100 = {overrun_pct}%
</calculations>
Generate a professional alert by following this structure :
1. **Opening Observation**: "Weekly consumption for {device} exceeded threshold: {Value} {unit} vs {threshold} {unit}"

2. **Contextual Note**: "This {overrun_pct}% overrun suggests potential efficiency improvements in energy usage patterns."

3. **Recommended Actions**:
"""
weekly_math_fr = """ 
Vous êtes un assistant chargé de générer des messages d’alerte sur la consommation d’énergie à partir de données structurées :
En utilisant ces données :
- Appareil : {device}
- Valeur mesurée : {Value} {unit}
- Seuil : {threshold} {unit}
- Calcul :le calcul doit etre entre <calculations></calculations> comme ca :
<calculations>
  Étape 1 : {Value} - {threshold} = {difference} {unit}
  Étape 2 : ({difference}/{threshold}) × 100 = {overrun_pct}%
génnérer une alerte  professionnelle en suivant cette structure :
1. **Observation** : "Dépassement hebdomadaire sur {device} : {Value} {unit} contre seuil {threshold} {unit}"

2. **Analyse** : "Dépassement de {overrun_pct}% indiquant des opportunités d'optimisation énergétique"

3. **Actions Recommandées**:
"""

subscribed_power_prompt_en_math = """
Using this data :
- Device: {device}
- Measured: {Value} {unit}
- Threshold: {threshold} {unit}
- Calculation: put the calculations steps always between <calculations></calculations> like this :
<calculations>
  {Value} - {threshold} = {difference} {unit}
  ({difference}/{threshold})×100 = {overrun_pct}%
</calculations>
Generate a professional alert by following this structure :
1. **Alert**: "{device} exceeded power limit: {Value} {unit} > {threshold} {unit}"
2. **Impact**: "{overrun_pct}% overrun may incur contractual penalties"
3. **Immediate Actions**:
4. **Long-term Solutions**: 
"""
subscribed_power_prompt_fr_math = """
En utilisant ces données :
- Appareil : {device}
- Mesure : {Value} {unit}
- Seuil : {threshold} {unit}
- Calcul : mettre tous le calcul entre <calculations></calculations> comme ca :
<calculations>
  {Value} - {threshold} = {difference} {unit}
  ({difference}/{threshold})×100 = {overrun_pct}%
</calculations>
génnérer une alerte  professionnelle en suivant cette structure :
1. **Alerte** : "Dépassement sur {device} : {Value} {unit} > {threshold} {unit}"
2. **Conséquences** : "Dépassement de {overrun_pct}% risquant des pénalités contractuelles"
3. **Actions Immédiates**:
4. **Solutions Durables**:
"""

day_alert_math = """
Using this data :
- Device: {device}
- Today: {today_consumption} {unit}
- Yesterday: {yesterday_consumption} {unit}
- Threshold: {threshold} {unit}
- Calculation:put the calculations between <calculations></calculations> like this :
<calculations>
  Variation = ({today_consumption}-{yesterday_consumption})/{yesterday_consumption}×100 = {variation_percent}%
</calculations>
Generate daily consumption alert by following this structure :
1. **Alert**: "Abnormal daily variation on {device}"
2. **Data** in a paraghraph:
   - Today: {today_consumption} {unit}
   - Yesterday: {yesterday_consumption} {unit}
   - Variation: {variation_percent}%
3. **Actions**:
"""
day_alert_fr_math = """
En utilisant ces données :
- Appareil : {device}
- Aujourd'hui : {today_consumption} {unit}
- Hier : {yesterday_consumption} {unit}
- Seuil : {threshold} {unit}
- Calcul :mettre tous le calcul entre <calculations></calculations> comme ca :
<calculations>
  Variation = ({today_consumption}-{yesterday_consumption})/{yesterday_consumption}×100 = {variation_percent}%
</calculations>
génnérer une alerte  professionnelle en suivant cette structure :
1. **Alerte** : "Variation journalière anormale sur {device}"
2. **Données** :
   - Aujourd'hui : {today_consumption} {unit}
   - Hier : {yesterday_consumption} {unit}
   - Variation : {variation_percent}%
3. **Actions** :
"""

ThisWeekVsLastWeek_alert_math = """ 
Using the following data:

Device: {device}

This week: {Value} {unit}

Last week: {previousWeekConsumption} {unit}

Threshold: {threshold} {unit}

Calculation: wrap the entire calculation inside <calculations></calculations> like this:
<calculations>
  Variation = ({Value} - {previousWeekConsumption}) / {previousWeekConsumption} × 100 = {variation_percent}%
</calculations>
Generate a professional weekly alert following this structure:

Alert: "Weekly anomaly detected on {device}"

Comparison (in a single paragraph):

Current: {Value} {unit}

Previous: {previousWeekConsumption} {unit}

Variation

Actions :
"""
ThisWeekVsLastWeek_alert_fr_math = """
En utilisant ces données :
- Appareil : {devicel}
- Cette semaine : {Value} {unit}
- Semaine dernière : {previousWeekConsumption} {unit}
- Seuil : {threshold} {unit}
- Calcul :mettre tous le calcul entre <calculations></calculations> comme ca :

<calculations>
  Variation = ({Value}-{previousWeekConsumption})/{previousWeekConsumption}×100 = {variation_percent}%
</calculations>
génnérer une alerte hebdomadaire  professionnelle en suivant cette structure :
1. **Alerte** : "Anomalie hebdomadaire sur {device}"
2. **Comparaison** ( dans une paraghraphe) :
   - Actuelle : {Value} {unit}
   - Précédente : {previousWeekConsumption} {unit}
   - Variation 
3. **Actions** :
"""

ThisWeekVsLastWeek_alert = """ 
Generate a formal, technical alert message (no greetings/bold text) for weekly consumption alert using the provided JSON data. Follow this structure:
1. **Alert context ** :
We've observed that the weekly consumption for {device} slightly exceeded ( or decressed ) the
threshold, registering {Value} {unit} compared to the threshold of {threshold} {unit}. This represents a
overrun of {weekly_variation}% , which may not necessarily indicate a significant issue ( or not selon the case ), but suggests an
potential area for efficiency improvements.
2. **recommendations** :
"""
ThisWeekVsLastWeek_alert_fr = """
Générer un message d'alerte formel et technique (sans salutations ni texte en gras) concernant la consommation hebdomadaire, en utilisant les données JSON fournies. Suivre la structure suivante :

Contexte de l’alerte :
Nous avons observé que la consommation hebdomadaire de {device} a légèrement dépassé (ou diminué par rapport à) le seuil, enregistrant {value} {unit} contre un seuil de {threshold} {unit}. Cela représente un écart de {weekly_variation}%, ce qui ne constitue pas nécessairement un problème significatif (ou non selon le cas), mais suggère un domaine potentiel d’amélioration de l’efficacité.

Recommandations  :
"""
def get_alert_prompt(alert_type: str, model: str, alert_data: dict = None) -> dict:
    """Return predefined prompts for alert types"""
    prompts = {
        "Weekly Consumption Alert": {
            "en": shared_alert_prompt_en,
            "fr": shared_alert_prompt_fr
        },
        "WeekThreshold": {
            "en": shared_alert_prompt_en,
            "fr": shared_alert_prompt_fr
        },
        "THDV":{
            "en": thdv_prompt_en,
            "fr": thdv_prompt_fr
        },
        "ExceededThreshold":{
            "en": thdv_prompt_en,
            "fr": thdv_prompt_fr
        },
        "SubscribedPower":{
            "en": subscribed_power_prompt_en,
            "fr": subscribed_power_prompt_fr
        },
        "Subscribed Power Exceeded":{
            "en": subscribed_power_prompt_en,
            "fr": subscribed_power_prompt_fr
        },
        "This Day vs Last Day Alert":{
            "en": day_alert,
            "fr": day_alert_fr
        },
        "CurrentDayVsLastDay":{
            "en": day_alert,
            "fr": day_alert_fr
        },
        "Power Factor - Cos Phi": {
            "en": cosphi_prompt,
            "fr": cosphi_prompt_fr
        },
        "CosphiThreshold": {
            "en": cosphi_prompt,
            "fr": cosphi_prompt_fr
        },
        "Inactive Device": {
            "en": inactive_prompt,
            "fr": inactive_prompt_fr
        },
        "ElectricityCuts":{
            "en": inactive_prompt,
            "fr": inactive_prompt_fr
        },
        "ThisWeekVsLastWeek":{
            "en": ThisWeekVsLastWeek_alert,
            "fr": ThisWeekVsLastWeek_alert_fr
        },
    }
    math_prompts = {
        "Weekly Consumption Alert": {
            "en": weekly_math,
            "fr": weekly_math_fr
        },
        "WeekThreshold": {
            "en": weekly_math,
            "fr": weekly_math_fr
        },
        "THDV":{
            "en": thdv_prompt_en,
            "fr": thdv_prompt_fr
        },
        "ExceededThreshold":{
            "en": thdv_prompt_en,
            "fr": thdv_prompt_fr
        },
        "SubscribedPower":{
            "en": subscribed_power_prompt_en_math,
            "fr": subscribed_power_prompt_fr_math
        },
        "Subscribed Power Exceeded":{
            "en": subscribed_power_prompt_en_math,
            "fr": subscribed_power_prompt_fr_math
        },
        "This Day vs Last Day Alert":{
            "en": day_alert_fr,
            "fr": day_alert_fr_math
        },
        "CurrentDayVsLastDay":{
            "en": day_alert_fr,
            "fr": day_alert_fr_math
        },
        "Power Factor - Cos Phi": {
            "en": cosphi_prompt,
            "fr": cosphi_prompt_fr
        },
        "CosphiThreshold": {
            "en": cosphi_prompt,
            "fr": cosphi_prompt_fr
        },
        "Inactive Device": {
            "en": inactive_prompt,
            "fr": inactive_prompt_fr
        },
        "ElectricityCuts":{
            "en": inactive_prompt,
            "fr": inactive_prompt_fr
        },
        "ThisWeekVsLastWeek":{
            "en": ThisWeekVsLastWeek_alert_math,
            "fr": ThisWeekVsLastWeek_alert_fr_math
        },
      }

    # Merge math prompts with base prompts if the model requires calculations
    if model.startswith("qwen2-math:latest"):
        for alert in math_prompts:
            if alert in prompts:
                prompts[alert]["en"] = math_prompts[alert].get("en", prompts[alert]["en"])
                prompts[alert]["fr"] = math_prompts[alert].get("fr", prompts[alert]["fr"])
            else:
                prompts[alert] = math_prompts[alert]


    return prompts.get(alert_type)