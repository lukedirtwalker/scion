from django.db import models
from ad_manager.util import monitoring_client


class ISD(models.Model):
    id = models.CharField(max_length=50, primary_key=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name = 'ISD'


class AD(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)

    def query_ad_status(self):
        return monitoring_client.get_ad_info(self.isd.id, self.id)

    def __str__(self):
        return '{}-{}'.format(self.isd.id, self.id)

    class Meta:
        verbose_name = 'AD'


class SCIONWebElement(models.Model):
    addr = models.IPAddressField()
    ad = models.ForeignKey(AD)

    def save(self, *args, **kwargs):
        if getattr(self, '_image_changed', True):
            pass
        super(SCIONWebElement, self).save(*args, **kwargs)

    def id_str(self):
        return "{}{}-{}-1".format(self.prefix, self.ad.isd_id, self.ad_id)

    def __str__(self):
        return '{} -- {}'.format(self.ad, self.addr)

    class Meta:
        abstract = True


class BeaconServerWeb(SCIONWebElement):
    prefix = 'bs'

    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = 'cs'

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr"),)


class PathServerWeb(SCIONWebElement):
    prefix = 'ps'

    class Meta:
        verbose_name = 'Path server'
        unique_together = (("ad", "addr"),)


class RouterWeb(SCIONWebElement):

    def id_str(self):
        return "er{}-{}er?-?".format(self.ad.isd_id, self.ad_id)

    class Meta:
        verbose_name = 'Router'
        unique_together = (("ad", "addr"),)
