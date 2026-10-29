Ext.namespace("SYNO.SDS.AutoBan.Utils");

Ext.define("SYNO.SDS.AutoBan.Application", {
    extend: "SYNO.SDS.AppInstance",
    appWindowName: "SYNO.SDS.AutoBan.MainWindow",
    constructor: function() {
        this.callParent(arguments);
    }
});

Ext.define("SYNO.SDS.AutoBan.MainWindow", {
    extend: "SYNO.SDS.AppWindow",
    constructor: function(a) {
        this.appInstance = a.appInstance;
        SYNO.SDS.AutoBan.MainWindow.superclass.constructor.call(this, Ext.apply({
            layout: "fit",
            resizable: true,
            cls: "syno-app-win",
            maximizable: true,
            minimizable: true,
            showHelp: false,
            width: 1152,
            height: 768,
            html: SYNO.SDS.AutoBan.Utils.getMainHtml()
        }, a));
        SYNO.SDS.AutoBan.Utils.ApplicationWindow = this;
    },

    onOpen: function() {
        SYNO.SDS.AutoBan.MainWindow.superclass.onOpen.apply(this, arguments);
    },

    onRequest: function(a) {
        SYNO.SDS.AutoBan.MainWindow.superclass.onRequest.call(this, a);
    },

    onClose: function() {
        SYNO.SDS.AutoBan.MainWindow.superclass.onClose.apply(this, arguments);
        this.doClose();
        return true;
    }
});

Ext.apply(SYNO.SDS.AutoBan.Utils, function() {
    return {
        getMainHtml: function() {
            return '<iframe src="/webman/3rdparty/AutoBan/index.cgi?_ts=' + new Date().getTime() + '" title="AutoBan" style="width: 100%; height: 100%; border: none; margin: 0"/>';
        }
    };
}());
